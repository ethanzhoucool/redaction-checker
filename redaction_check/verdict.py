"""Snapshot leak evaluation heuristics.

Given a decoded app-switcher / recents snapshot (and optionally the live
foregrounded screen + the on-disk compressed size), decide whether sensitive
content leaked into the backgrounded card.

A snapshot is a LEAK (FAIL) when it shows readable / sensitive content; it is
SAFE (PASS) when it is blank, solid-black, or heavily blurred and carries no
secret matches. See OWASP MASVS MSTG-STORAGE-9 / PCI: sensitive data must be
removed from views when the app is backgrounded.
"""
from __future__ import annotations

from typing import Optional

import numpy as np
import pytesseract
from PIL import Image

from redaction_check.contract import (
    PASS,
    FAIL,
    ERROR,
    Verdict,
    compile_secret_patterns,
)

# --- Tuned thresholds (module constants, documented) ------------------------
# Grayscale std-dev below this reads as a solid / flat card (black, white, blur
# of a single colour). loop_blank.png measures exactly 0.0; real content (e.g.
# expo_content.png) measures ~26.
BLANK_STDDEV = 5.0

# Variance-of-Laplacian below this means the image carries almost no edges, i.e.
# it is blurred or flat. Used to recognise heavily-blurred (privacy-screen)
# snapshots as SAFE even if OCR coughs up a stray char.
BLUR_VAR_LAPLACIAN = 100.0

# A compressed AAPL/LZFSE payload smaller than this is a near-empty card. A real
# leak compresses far larger; a blanked card crushes to a few KB.
BLANK_COMPRESSED_BYTES = 4000

# Mean absolute grayscale diff (0..1) below this means the snapshot is
# effectively identical to the live screen -> the OS captured the real content.
DIFF_LEAK_RATIO = 0.08

# OCR character count at/above this is "readable text" -> treat as a leak.
READABLE_OCR_CHARS = 12

# Common small canvas both images are squished to for the diff comparison.
_DIFF_SIZE = (64, 64)


def _to_gray_array(image: Image.Image) -> np.ndarray:
    return np.asarray(image.convert("L"), dtype=np.float64)


def _pixel_stddev(gray: np.ndarray) -> float:
    return float(gray.std())


def _variance_of_laplacian(gray: np.ndarray) -> float:
    """Edge energy. Low => flat/blurred, high => crisp content."""
    # 3x3 Laplacian kernel applied via numpy (no scipy/cv2 dependency).
    k = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float64)
    g = gray
    if g.shape[0] < 3 or g.shape[1] < 3:
        return 0.0
    # 'valid' 2D convolution without scipy: shift-and-add the 4-neighbourhood.
    center = g[1:-1, 1:-1]
    lap = (
        g[:-2, 1:-1]
        + g[2:, 1:-1]
        + g[1:-1, :-2]
        + g[1:-1, 2:]
        - 4.0 * center
    )
    return float(lap.var())


def _diff_ratio(snapshot: Image.Image, live: Image.Image) -> float:
    a = np.asarray(snapshot.convert("L").resize(_DIFF_SIZE), dtype=np.float64)
    b = np.asarray(live.convert("L").resize(_DIFF_SIZE), dtype=np.float64)
    return float(np.abs(a - b).mean() / 255.0)


def evaluate(
    snapshot: Optional[Image.Image],
    *,
    live: Optional[Image.Image] = None,
    compressed_bytes: Optional[int] = None,
    secret_patterns: Optional[list[str]] = None,
) -> Verdict:
    """Evaluate a decoded snapshot for a sensitive-content leak.

    Returns a Verdict whose ``metrics`` records every numeric signal and whose
    ``reasons`` explains the decision in human terms.
    """
    metrics: dict = {}
    reasons: list[str] = []
    leaked_text: list[str] = []

    if compressed_bytes is not None:
        metrics["compressed_bytes"] = int(compressed_bytes)

    # --- ERROR: nothing to inspect -----------------------------------------
    if snapshot is None:
        reasons.append("No snapshot image available to inspect.")
        return Verdict(status=ERROR, reasons=reasons, leaked_text=leaked_text, metrics=metrics)

    gray = _to_gray_array(snapshot)

    # --- OCR ----------------------------------------------------------------
    try:
        ocr_text = pytesseract.image_to_string(snapshot)
    except Exception as exc:  # pragma: no cover - tesseract misconfig
        reasons.append(f"OCR failed: {exc}")
        ocr_text = ""
    ocr_text_stripped = ocr_text.strip()
    ocr_chars = len(ocr_text_stripped)
    metrics["ocr_text"] = ocr_text
    metrics["ocr_chars"] = ocr_chars

    # --- secret-pattern matches --------------------------------------------
    patterns = compile_secret_patterns(secret_patterns)
    for pat in patterns:
        for m in pat.findall(ocr_text):
            hit = m if isinstance(m, str) else "".join(m)
            hit = hit.strip()
            if hit and hit not in leaked_text:
                leaked_text.append(hit)
    leak_hits = len(leaked_text)
    metrics["leak_hits"] = leak_hits

    # --- pixel / blur signals ----------------------------------------------
    pixel_stddev = _pixel_stddev(gray)
    blur = _variance_of_laplacian(gray)
    metrics["pixel_stddev"] = round(pixel_stddev, 4)
    metrics["blur"] = round(blur, 4)

    # --- blank detection ----------------------------------------------------
    # A snapshot only counts as "blank" when it carries no readable text. A small
    # or flat card that STILL shows readable content is not blank and must reach
    # the leak checks below — otherwise a tiny-but-readable leak (e.g. a balance
    # on a solid background, <4 KB) would be silently passed.
    no_readable = ocr_chars < READABLE_OCR_CHARS
    small_payload = compressed_bytes is not None and compressed_bytes < BLANK_COMPRESSED_BYTES
    blank = no_readable and (pixel_stddev < BLANK_STDDEV or small_payload)
    metrics["blank"] = bool(blank)

    heavily_blurred = blur < BLUR_VAR_LAPLACIAN
    metrics["heavily_blurred"] = bool(heavily_blurred)

    # --- live-screen similarity --------------------------------------------
    diff_ratio: Optional[float] = None
    if live is not None:
        diff_ratio = _diff_ratio(snapshot, live)
        metrics["diff_ratio"] = round(diff_ratio, 4)

    # --- decision -----------------------------------------------------------
    if leak_hits:
        reasons.append(
            f"Secret pattern(s) matched in snapshot OCR: {', '.join(leaked_text)}."
        )
        return Verdict(status=FAIL, reasons=reasons, leaked_text=leaked_text, metrics=metrics)

    if (
        not blank
        and diff_ratio is not None
        and diff_ratio < DIFF_LEAK_RATIO
    ):
        reasons.append(
            f"Snapshot closely matches the live screen (diff_ratio="
            f"{diff_ratio:.4f} < {DIFF_LEAK_RATIO}); the real content was captured."
        )
        return Verdict(status=FAIL, reasons=reasons, leaked_text=leaked_text, metrics=metrics)

    if not blank and ocr_chars >= READABLE_OCR_CHARS:
        snippet = ocr_text_stripped.replace("\n", " ")[:80]
        reasons.append(
            f"Readable text in snapshot ({ocr_chars} chars >= {READABLE_OCR_CHARS}): "
            f"\"{snippet}\"."
        )
        return Verdict(status=FAIL, reasons=reasons, leaked_text=leaked_text, metrics=metrics)

    # --- PASS ---------------------------------------------------------------
    if blank:
        reasons.append(
            f"Snapshot is blank/solid (pixel_stddev={pixel_stddev:.2f}, "
            f"ocr_chars={ocr_chars}); no readable content."
        )
    elif heavily_blurred:
        reasons.append(
            f"Snapshot is heavily blurred (blur={blur:.1f} < {BLUR_VAR_LAPLACIAN}) "
            f"with no secret matches."
        )
    else:
        reasons.append(
            f"No secret matches and too little readable text to constitute a leak "
            f"(ocr_chars={ocr_chars} < {READABLE_OCR_CHARS})."
        )
    return Verdict(status=PASS, reasons=reasons, leaked_text=leaked_text, metrics=metrics)
