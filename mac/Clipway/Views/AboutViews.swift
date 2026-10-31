import ClipwayCore
import SwiftUI

/// About: the same screen in every app of Sid's (principles, version, security, links, Erase everything).
struct AboutView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.router) private var router
    @State private var erasing = false
    var scrolls = true
    private let signature = CodeSignature.current()

    static let principles = [
        "Your data belongs to you.",
        "No account. No tracking. No ads.",
        "Nothing leaves your device unless you choose it.",
        "The code will be published, so anyone can check this.",
    ]

    static var reviewDate: String {
        let parse = DateFormatter()
        parse.locale = Locale(identifier: "en_US_POSIX")
        parse.dateFormat = "yyyy-MM-dd"
        let show = DateFormatter()
        show.locale = Locale(identifier: "en_US_POSIX")
        show.dateFormat = "d MMM yyyy"
        guard let date = parse.date(from: ClipwayInfo.lastSecurityReview) else { return ClipwayInfo.lastSecurityReview }
        return show.string(from: date)
    }

    var body: some View {
        Scrolling(enabled: scrolls, height: Tokens.Size.tallWindow) {
            VStack(alignment: .leading, spacing: Tokens.Space.l) {
                HStack(spacing: Tokens.Space.m) {
                    // The bundle's icon as Finder draws it (applicationIconImage can be the generic one for a menu bar app).
                    Image(nsImage: NSWorkspace.shared.icon(forFile: Bundle.main.bundlePath))
                        .resizable()
                        .frame(width: Tokens.Size.heroIcon, height: Tokens.Size.heroIcon)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: Tokens.Space.xxs) {
                        Text("Clipway")
                            .font(Tokens.Typography.largeTitle)
                            .tracking(Tokens.Typography.largeTitleTracking)
                        Text("Your clipboard, on your Mac and your phone.")
                            .foregroundStyle(Tokens.Colors.secondaryText)
                    }
                }

                SectionTitle("Our principles")
                Card {
                    ForEach(Self.principles, id: \.self) { line in
                        IconText(line, symbol: "checkmark", symbolColor: Tokens.Colors.success)
                    }
                }

                SectionTitle("Version")
                Card {
                    HStack {
                        Text("Version \(AppModel.version)")
                        Spacer()
                        Button("What's new") { router?.show(.changelog) }
                            .buttonStyle(.secondary)
                    }
                }

                SectionTitle("Security")
                Card {
                    VStack(alignment: .leading, spacing: Tokens.Space.xxs) {
                        Text("Last security review: \(Self.reviewDate)")
                        Text("Internal review. No external audit yet.")
                            .font(Tokens.Typography.callout)
                            .foregroundStyle(Tokens.Colors.secondaryText)
                    }
                    Divider()
                    HStack(alignment: .firstTextBaseline) {
                        VStack(alignment: .leading, spacing: Tokens.Space.xxs) {
                            Text("Code signature")
                            Text(signatureDetail)
                                .font(Tokens.Typography.callout)
                                .foregroundStyle(Tokens.Colors.secondaryText)
                        }
                        Spacer()
                        Text(signature.map { CodeSignature.short($0.cdhash) } ?? "unsigned")
                            .font(Tokens.Typography.mono)
                            .textSelection(.enabled)
                    }
                    Divider()
                    Button("Report a security issue") { open(mail: "Clipway security issue") }
                        .buttonStyle(.quiet)
                }

                SectionTitle("Links")
                Card {
                    Button("What leaves your device") { router?.show(.whatLeaves) }
                        .buttonStyle(.quiet)
                    Button("Privacy policy") { router?.show(.privacy) }
                        .buttonStyle(.quiet)
                    Button("Contact") { open(mail: "Clipway") }
                        .buttonStyle(.quiet)
                }

                Button("Erase everything") { erasing = true }
                    .buttonStyle(.destructive)
                    .padding(.top, Tokens.Space.s)

                Text("Made by Sid · sidali.dev")
                    .font(Tokens.Typography.footnote)
                    .foregroundStyle(Tokens.Colors.tertiaryText)
                    .frame(maxWidth: .infinity)
                Text("Fonts: Bricolage Grotesque and Figtree, SIL Open Font License.")
                    .font(Tokens.Typography.caption)
                    .foregroundStyle(Tokens.Colors.tertiaryText)
                    .frame(maxWidth: .infinity)
            }
            .font(Tokens.Typography.body)
            .padding(.horizontal, Tokens.Space.xxl)
            .padding(.top, Tokens.Space.titlebar)
            .padding(.bottom, Tokens.Space.xxl)
        }
        .sheet(isPresented: $erasing) { EraseSheet().frame(width: Tokens.Size.windowWidth) }
    }

    private var signatureDetail: String {
        guard let signature else { return "Not signed." }
        return signature.adHoc
            ? "Ad hoc signature, no Apple certificate. Compare this code directory hash with the release notes."
            : "Signed. Compare this code directory hash with the release notes."
    }

    private func open(mail subject: String) {
        let encoded = subject.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? subject
        if let url = URL(string: "mailto:\(ClipwayInfo.contact)?subject=\(encoded)") { NSWorkspace.shared.open(url) }
    }
}

/// Erase everything: confirmed by typing ERASE.
struct EraseSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.router) private var router
    @Environment(\.dismiss) private var dismiss
    @State private var typed = ""
    @State private var working = false

    static let facts = [
        "This Mac forgets the key, the history and the settings. The keys are destroyed, so nothing left on the disk can be read.",
        "The relay is asked to erase what it holds for your chain. Without network, it erases it within 24 hours.",
        "Files in Downloads, Clipway folder, stay: they are yours. Your phone keeps the key until you erase it there too.",
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.Space.l) {
            Text("Erase everything")
                .font(Tokens.Typography.title)
                .foregroundStyle(Tokens.Colors.danger)
            VStack(alignment: .leading, spacing: Tokens.Space.s) {
                ForEach(Self.facts, id: \.self) { fact in
                    Text(fact)
                        .font(Tokens.Typography.callout)
                        .foregroundStyle(Tokens.Colors.secondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            TextField("Type ERASE to confirm", text: $typed)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
            HStack {
                Button("Cancel") { dismiss() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button(working ? "Erasing" : "Erase everything") { erase() }
                    .buttonStyle(ClipButtonStyle(kind: .destructive))
                    .disabled(typed != "ERASE" || working)
            }
        }
        .padding(Tokens.Space.xxl)
    }

    private func erase() {
        working = true
        Task {
            _ = await model.eraseEverything()
            Haptics.success()
            dismiss()
            router?.closeAll()
            router?.show(.welcome)
        }
    }
}

/// What leaves your device: what, to where, encrypted or not. Same facts as PRIVACY.md.
struct WhatLeavesView: View {
    @Environment(AppModel.self) private var model
    var scrolls = true

    var body: some View {
        Scrolling(enabled: scrolls, height: Tokens.Size.scrollingWindow) {
            VStack(alignment: .leading, spacing: Tokens.Space.l) {
                Text("What leaves your device")
                    .font(Tokens.Typography.largeTitle)
                    .tracking(Tokens.Typography.largeTitleTracking)
                Card {
                    InfoRow(symbol: "arrow.up.circle", title: "What you copy",
                            detail: "When Send automatically is on: texts up to 64 KB, to the relay \(model.relayHost), end-to-end encrypted: only your devices hold the key.")
                    InfoRow(symbol: "wifi", title: "Images and files: never on a server",
                            detail: "They go straight from this Mac to your phone over your local network, encrypted with a key made for that one transfer. The relay only passes a short encrypted note that tells your phone where to fetch it, so both devices need to be on the same network. Nobody can check what travels encrypted without an account, so our relay refuses to carry pictures or files at all.")
                    InfoRow(symbol: "eye", title: "What the relay sees",
                            detail: "A random chain id, the time and size of each item, how many of your devices are connected, and your IP address while connected. It never sees the content, file names or device names, nor whether an item is a text or a note about a file.")
                    InfoRow(symbol: "clock", title: "How long",
                            detail: "Up to 24 hours, in the relay's memory, for a device that is offline. Then it is erased. The relay never logs your IP address. On clip.sidali.dev, the web server in front of it keeps IP addresses for 7 days.")
                    InfoRow(symbol: "dot.radiowaves.left.and.right", title: "The relay's status",
                            detail: "Once a day, Clipway asks the relay if it is up and which app versions it accepts. No key and no content, only the app's name and version.")
                    InfoRow(symbol: "antenna.radiowaves.left.and.right", title: "Bluetooth, only while you pair",
                            detail: "While the Pair nearby window is open, 2 minutes at most, devices in Bluetooth range can see that a Clipway Mac is pairing and read its Bluetooth name. The key goes to your phone encrypted, only after you press Pair on both. No location is collected, and nothing about it is stored.")
                    InfoRow(symbol: "hand.raised", title: "Never sent",
                            detail: "What password managers mark as concealed or transient, content marked as auto-generated, and Finder copies of files unless you send them.",
                            symbolColor: Tokens.Colors.success)
                    InfoRow(symbol: "desktopcomputer", title: "Your Mac's name",
                            detail: "\"\(model.deviceName)\" and a random device id, inside the encryption, for your other devices only.")
                    InfoRow(symbol: "nosign", title: "Nothing else",
                            detail: "No account, no analytics, no crash reports, no third-party services.")
                }
                SectionTitle("Stays on this Mac")
                Card {
                    InfoRow(symbol: "key", title: "The key",
                            detail: "In the Keychain of this Mac, never synced to iCloud.")
                    InfoRow(symbol: "clock.arrow.circlepath", title: "History",
                            detail: "The last 50 items, encrypted. Erase everything destroys the key, which makes it unreadable.")
                    InfoRow(symbol: "folder", title: "Received files",
                            detail: "In Downloads, Clipway folder. They are yours: Erase everything leaves them.")
                    InfoRow(symbol: "network", title: "Listening, only while it sends",
                            detail: "While it offers an image or a file, 2 minutes at most, this Mac accepts one connection from your phone on the local network. Without the key, a connection gets nothing.")
                }
            }
            .padding(.horizontal, Tokens.Space.xxl)
            .padding(.top, Tokens.Space.titlebar)
            .padding(.bottom, Tokens.Space.xxl)
        }
    }
}

/// A Markdown document shipped in the app (CHANGELOG.md, PRIVACY.md), rendered simply.
struct DocumentView: View {
    let resource: String

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Tokens.Space.s) {
                ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                    row(line)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Tokens.Space.xxl)
            .padding(.top, Tokens.Space.titlebar)
            .padding(.bottom, Tokens.Space.xxl)
        }
        .frame(height: Tokens.Size.scrollingWindow)
    }

    private var lines: [String] {
        guard let url = Bundle.main.url(forResource: resource, withExtension: "md"),
              let text = try? String(contentsOf: url, encoding: .utf8)
        else { return ["This document is missing from the app."] }
        return text.components(separatedBy: "\n").filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    @ViewBuilder
    private func row(_ line: String) -> some View {
        if line.hasPrefix("# ") {
            Text(String(line.dropFirst(2)))
                .font(Tokens.Typography.largeTitle)
                .tracking(Tokens.Typography.largeTitleTracking)
        } else if line.hasPrefix("## ") {
            Text(String(line.dropFirst(3)))
                .font(Tokens.Typography.title)
                .padding(.top, Tokens.Space.m)
        } else if line.hasPrefix("- ") {
            HStack(alignment: .firstTextBaseline, spacing: Tokens.Space.s) {
                Text("•").foregroundStyle(Tokens.Colors.secondaryText)
                Text(inline(String(line.dropFirst(2))))
            }
            .font(Tokens.Typography.body)
        } else {
            Text(inline(line))
                .font(Tokens.Typography.body)
        }
    }

    private func inline(_ text: String) -> AttributedString {
        (try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)))
            ?? AttributedString(text)
    }
}
