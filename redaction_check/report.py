"""Evidence rendering + report generation for redaction-checker.

Produces:
  - per-screen side-by-side evidence PNGs (live screen vs. backgrounded
    snapshot, with a PASS/FAIL banner and the key metrics);
  - a report.md and a report.html summarising every screen with an overall
    PASS/FAIL verdict.

Compliance framing (cited in the report header): OWASP MASVS MSTG-STORAGE-9 /
PCI — sensitive data must be removed from views when the app is backgrounded.
"""
from __future__ import annotations

import html
import os
from pathlib import Path
from typing import Optional

from PIL import Image, ImageDraw, ImageFont

from redaction_check.contract import PASS, FAIL, ERROR, ScreenResult

# --- layout constants -------------------------------------------------------
_PANEL_W = 360          # width of each image panel
_PANEL_H = 760          # height of each image panel
_PAD = 16
_BANNER_H = 56
_FOOTER_LINE_H = 18

_COLORS = {
    PASS: (32, 148, 72),
    FAIL: (196, 42, 42),
    ERROR: (176, 120, 16),
}
_BG = (24, 24, 28)
_FG = (235, 235, 240)
_PANEL_BG = (44, 44, 52)

_OWASP_HEADER = (
    "OWASP MASVS MSTG-STORAGE-9 / PCI — sensitive data must be removed from "
    "views when the app is backgrounded (app-switcher / recents snapshot)."
)


def _font(size: int) -> ImageFont.ImageFont:
    try:
        return ImageFont.truetype("Helvetica.ttc", size)
    except Exception:
        try:
            return ImageFont.truetype("DejaVuSans.ttf", size)
        except Exception:
            return ImageFont.load_default()


def _load(path: Optional[str]) -> Optional[Image.Image]:
    if not path:
        return None
    try:
        return Image.open(path).convert("RGB")
    except Exception:
        return None


def _fit(img: Image.Image, box_w: int, box_h: int) -> Image.Image:
    img = img.copy()
    img.thumbnail((box_w, box_h))
    return img


def _placeholder(box_w: int, box_h: int, label: str) -> Image.Image:
    ph = Image.new("RGB", (box_w, box_h), _PANEL_BG)
    d = ImageDraw.Draw(ph)
    f = _font(20)
    tw = d.textlength(label, font=f)
    d.text(((box_w - tw) / 2, box_h / 2 - 12), label, fill=(150, 150, 158), font=f)
    return ph


def _paste_panel(canvas: Image.Image, x: int, y: int, title: str,
                 img: Optional[Image.Image]) -> None:
    d = ImageDraw.Draw(canvas)
    d.rectangle([x, y, x + _PANEL_W, y + _PANEL_H + 28], fill=_PANEL_BG)
    f = _font(16)
    d.text((x + 8, y + 4), title, fill=_FG, font=f)
    inner_w, inner_h = _PANEL_W - 2 * 8, _PANEL_H - 8
    if img is None:
        content = _placeholder(inner_w, inner_h, "n/a")
    else:
        content = _fit(img, inner_w, inner_h)
    cx = x + 8 + (inner_w - content.width) // 2
    cy = y + 28 + (inner_h - content.height) // 2
    canvas.paste(content, (cx, cy))


def build_evidence(result: ScreenResult, out_path: os.PathLike | str) -> Path:
    """Render a side-by-side evidence PNG for a single screen result.

    Left panel: live foregrounded screen (or an "n/a" placeholder).
    Right panel: decoded backgrounded snapshot.
    Top banner: PASS/FAIL/ERROR plus screen name + platform.
    Footer: leaked_text and key metrics drawn onto the image.
    """
    out_path = Path(out_path)
    v = result.verdict
    status = v.status

    footer_lines = [
        f"Reasons: {' '.join(v.reasons) if v.reasons else '(none)'}",
        f"Leaked text: {', '.join(v.leaked_text) if v.leaked_text else '(none)'}",
        "Metrics: " + _format_metrics(v.metrics),
    ]
    # naive wrap so long reasons stay on-canvas
    wrapped: list[str] = []
    max_chars = 92
    for line in footer_lines:
        while len(line) > max_chars:
            cut = line.rfind(" ", 0, max_chars)
            cut = cut if cut > 0 else max_chars
            wrapped.append(line[:cut])
            line = line[cut:].lstrip()
        wrapped.append(line)

    total_w = _PANEL_W * 2 + _PAD * 3
    footer_h = _FOOTER_LINE_H * len(wrapped) + _PAD
    total_h = _BANNER_H + _PANEL_H + 28 + footer_h + _PAD * 2

    canvas = Image.new("RGB", (total_w, total_h), _BG)
    d = ImageDraw.Draw(canvas)

    # banner
    banner_color = _COLORS.get(status, (90, 90, 96))
    d.rectangle([0, 0, total_w, _BANNER_H], fill=banner_color)
    bf = _font(26)
    title = f"{status}  —  {result.name}  [{result.platform}]"
    d.text((_PAD, (_BANNER_H - 28) / 2), title, fill=(255, 255, 255), font=bf)

    # panels
    py = _BANNER_H + _PAD
    _paste_panel(canvas, _PAD, py, "LIVE SCREEN", _load(result.live_image))
    _paste_panel(canvas, _PAD * 2 + _PANEL_W, py, "BACKGROUNDED SNAPSHOT",
                 _load(result.snapshot_image))

    # footer
    ff = _font(13)
    fy = py + _PANEL_H + 28 + _PAD // 2
    for ln in wrapped:
        d.text((_PAD, fy), ln, fill=_FG, font=ff)
        fy += _FOOTER_LINE_H

    out_path.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(out_path)
    return out_path


def _format_metrics(metrics: dict) -> str:
    parts = []
    for key in ("ocr_chars", "leak_hits", "pixel_stddev", "blur",
                "diff_ratio", "compressed_bytes", "blank"):
        if key in metrics:
            parts.append(f"{key}={metrics[key]}")
    return ", ".join(parts) if parts else "(none)"


def _overall_status(results: list[ScreenResult]) -> str:
    statuses = {r.verdict.status for r in results}
    if FAIL in statuses:
        return FAIL
    if ERROR in statuses and PASS not in statuses:
        return ERROR
    if ERROR in statuses:
        return FAIL  # be conservative: an error among passes is not a clean pass
    return PASS


def write_report(results: list[ScreenResult], out_dir: os.PathLike | str) -> dict:
    """Write report.md + report.html (and evidence PNGs) into ``out_dir``.

    Returns a dict of the paths written.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    overall = _overall_status(results)
    evidence_paths: dict[str, Path] = {}
    for r in results:
        ev = out_dir / f"evidence_{_slug(r.name)}.png"
        build_evidence(r, ev)
        evidence_paths[r.name] = ev

    md_path = out_dir / "report.md"
    html_path = out_dir / "report.html"
    md_path.write_text(_render_md(results, overall, evidence_paths, out_dir))
    html_path.write_text(_render_html(results, overall, evidence_paths, out_dir))

    return {
        "report_md": md_path,
        "report_html": html_path,
        "evidence": evidence_paths,
    }


def _slug(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name).strip("_").lower() or "screen"


def _render_md(results, overall, evidence_paths, out_dir) -> str:
    lines: list[str] = []
    lines.append("# Redaction Check Report")
    lines.append("")
    lines.append(f"**Overall: {overall}**")
    lines.append("")
    lines.append("> " + _OWASP_HEADER)
    lines.append("")
    lines.append(f"Screens checked: {len(results)} | "
                 f"FAIL: {sum(1 for r in results if r.verdict.status == FAIL)} | "
                 f"PASS: {sum(1 for r in results if r.verdict.status == PASS)} | "
                 f"ERROR: {sum(1 for r in results if r.verdict.status == ERROR)}")
    lines.append("")
    for r in results:
        v = r.verdict
        lines.append(f"## {r.verdict.status} — {r.name} ({r.platform})")
        lines.append("")
        lines.append(f"- **Sensitive screen:** {r.sensitive}")
        lines.append(f"- **Verdict:** {v.status}")
        if v.reasons:
            lines.append("- **Reasons:**")
            for reason in v.reasons:
                lines.append(f"  - {reason}")
        leaked = ", ".join(v.leaked_text) if v.leaked_text else "(none)"
        lines.append(f"- **Leaked text:** {leaked}")
        lines.append(f"- **Metrics:** {_format_metrics(v.metrics)}")
        ev = evidence_paths.get(r.name)
        if ev:
            rel = os.path.relpath(ev, out_dir)
            lines.append("")
            lines.append(f"![evidence for {r.name}]({rel})")
        lines.append("")
    return "\n".join(lines) + "\n"


def _render_html(results, overall, evidence_paths, out_dir) -> str:
    color = {PASS: "#209448", FAIL: "#c42a2a", ERROR: "#b07810"}.get(overall, "#5a5a60")
    fail_n = sum(1 for r in results if r.verdict.status == FAIL)
    pass_n = sum(1 for r in results if r.verdict.status == PASS)
    err_n = sum(1 for r in results if r.verdict.status == ERROR)

    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>Redaction Check Report</title>")
    parts.append(
        "<style>"
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;"
        "background:#18181c;color:#ebebf0;}"
        ".wrap{max-width:980px;margin:0 auto;padding:24px;}"
        ".overall{display:inline-block;padding:8px 18px;border-radius:8px;"
        "font-weight:700;font-size:20px;color:#fff;}"
        ".note{color:#b8b8c0;font-size:14px;margin:14px 0 4px;}"
        ".card{background:#26262e;border-radius:12px;padding:18px;margin:18px 0;}"
        ".badge{display:inline-block;padding:3px 12px;border-radius:6px;"
        "font-weight:700;color:#fff;font-size:14px;}"
        ".meta{color:#c2c2cc;font-size:13px;margin-top:8px;}"
        ".leak{color:#ff8a8a;font-weight:600;}"
        "code{background:#101014;padding:1px 5px;border-radius:4px;}"
        "img{max-width:100%;border-radius:8px;margin-top:12px;border:1px solid #333;}"
        "ul{margin:6px 0;}"
        "</style></head><body><div class='wrap'>"
    )
    parts.append("<h1>Redaction Check Report</h1>")
    parts.append(
        f"<span class='overall' style='background:{color}'>Overall: {overall}</span>"
    )
    parts.append(f"<p class='note'>{html.escape(_OWASP_HEADER)}</p>")
    parts.append(
        f"<p class='note'>Screens checked: {len(results)} &middot; "
        f"FAIL: {fail_n} &middot; PASS: {pass_n} &middot; ERROR: {err_n}</p>"
    )

    for r in results:
        v = r.verdict
        bcolor = _hex(v.status)
        parts.append("<div class='card'>")
        parts.append(
            f"<span class='badge' style='background:{bcolor}'>{v.status}</span> "
            f"<strong>{html.escape(r.name)}</strong> "
            f"<span class='meta'>[{html.escape(r.platform)}] "
            f"sensitive={r.sensitive}</span>"
        )
        if v.reasons:
            parts.append("<ul>")
            for reason in v.reasons:
                parts.append(f"<li>{html.escape(reason)}</li>")
            parts.append("</ul>")
        if v.leaked_text:
            parts.append(
                "<p class='leak'>Leaked text: "
                + html.escape(", ".join(v.leaked_text))
                + "</p>"
            )
        else:
            parts.append("<p class='meta'>Leaked text: (none)</p>")
        parts.append(
            f"<p class='meta'>Metrics: <code>"
            f"{html.escape(_format_metrics(v.metrics))}</code></p>"
        )
        ev = evidence_paths.get(r.name)
        if ev:
            rel = os.path.relpath(ev, out_dir)
            parts.append(
                f"<img src='{html.escape(rel)}' alt='evidence for "
                f"{html.escape(r.name)}'>"
            )
        parts.append("</div>")

    parts.append("</div></body></html>")
    return "".join(parts)


def _hex(status: str) -> str:
    return {PASS: "#209448", FAIL: "#c42a2a", ERROR: "#b07810"}.get(status, "#5a5a60")
