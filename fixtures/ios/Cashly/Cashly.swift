import SwiftUI

enum Route: String { case home, leaky, redacted }

final class Router: ObservableObject {
    @Published var route: Route
    init() {
        // Driven by simctl launch args ("leaky"/"redacted") or a deep link.
        let args = CommandLine.arguments.map { $0.lowercased() }
        if args.contains("redacted") { route = .redacted }
        else if args.contains("leaky") { route = .leaky }
        else { route = .home }
        print("[Cashly] launch route=\(route.rawValue)")
    }
    func handle(_ url: URL) {
        let s = url.absoluteString.lowercased()
        route = s.contains("redacted") ? .redacted : (s.contains("leaky") ? .leaky : .home)
        print("[Cashly] onOpenURL \(s) route=\(route.rawValue)")
    }
}

@main
struct CashlyApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var router = Router()
    var body: some Scene {
        WindowGroup {
            ZStack {
                RootView().environmentObject(router)
                // Privacy cover: ONLY the redacted route obscures itself when the scene
                // is not active. The leaky route deliberately does not -> its app-switcher
                // snapshot leaks. This is the whole point of the fixture.
                if router.route == .redacted && scenePhase != .active {
                    PrivacyCover()
                }
            }
            .onOpenURL { router.handle($0) }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var router: Router
    var body: some View {
        switch router.route {
        case .home: HomeView()
        case .leaky, .redacted: PaymentView(secured: router.route == .redacted)
        }
    }
}

struct HomeView: View {
    @EnvironmentObject var router: Router
    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "creditcard.fill").font(.system(size: 64)).foregroundStyle(.tint)
            Text("Cashly").font(.largeTitle.bold())
            Text("Mock payments — redaction fixture").font(.subheadline).foregroundStyle(.secondary)
            Spacer()
            Button { router.route = .leaky } label: {
                Label("Add card (leaky)", systemImage: "exclamationmark.triangle.fill").frame(maxWidth: .infinity)
            }.buttonStyle(.borderedProminent).tint(.red)
            Button { router.route = .redacted } label: {
                Label("Add card (redacted)", systemImage: "checkmark.shield.fill").frame(maxWidth: .infinity)
            }.buttonStyle(.borderedProminent).tint(.green)
            Spacer()
        }.padding()
    }
}

struct PaymentView: View {
    @EnvironmentObject var router: Router
    let secured: Bool
    var body: some View {
        NavigationStack {
            Form {
                Section("Payment card") {
                    LabeledContent("Card number", value: "4242 4242 4242 4242")
                    LabeledContent("Expires", value: "12/27")
                    LabeledContent("CVV", value: "311")
                    LabeledContent("Cardholder", value: "ETHAN ZHOU")
                }
                Section("Identity verification") {
                    LabeledContent("SSN", value: "123-45-6789")
                    LabeledContent("Date of birth", value: "04/12/1998")
                }
                Section {
                    Text(secured
                         ? "This screen obscures itself in the app switcher."
                         : "This screen does NOT obscure itself in the app switcher.")
                        .font(.footnote).foregroundStyle(secured ? .green : .red)
                }
            }
            .navigationTitle(secured ? "Add Card (secured)" : "Add Card")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { router.route = .home } label: {
                        Label("Back", systemImage: "chevron.left")
                    }
                }
            }
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 12) {
                Image(systemName: "lock.fill").font(.system(size: 48)).foregroundStyle(.white)
                Text("Cashly").font(.title2.bold()).foregroundStyle(.white)
            }
        }
    }
}
