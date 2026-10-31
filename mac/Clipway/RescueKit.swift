import AppKit
import ClipwayCore
import SwiftUI

/// The rescue kit, printed (or saved as PDF from the print panel): the 12 numbered words and the
/// QR code, then a page for someone you trust.
@MainActor
enum RescueKit {
    static func print(keys: ChainKeys, relay: String) {
        guard let info = NSPrintInfo.shared.copy() as? NSPrintInfo else { return }
        info.topMargin = 0
        info.bottomMargin = 0
        info.leftMargin = 0
        info.rightMargin = 0
        info.horizontalPagination = .clip
        info.verticalPagination = .clip
        info.isHorizontallyCentered = true
        info.isVerticallyCentered = false
        let view = PagedView(pages: pages(keys: keys, relay: relay, size: info.paperSize), pageSize: info.paperSize)
        let operation = NSPrintOperation(view: view, printInfo: info)
        operation.jobTitle = "Clipway rescue kit"
        operation.showsPrintPanel = true
        operation.showsProgressPanel = false
        NSApp.activate()
        operation.run()
    }

    static func pages(keys: ChainKeys, relay: String, size: CGSize) -> [AnyView] {
        [
            AnyView(KeyPage(keys: keys, relay: relay).frame(width: size.width, height: size.height)),
            AnyView(TrustPage(relay: relay).frame(width: size.width, height: size.height)),
        ]
    }
}

/// Pages stacked vertically, one page each.
final class PagedView: NSView {
    private let pageSize: CGSize
    private let count: Int

    init(pages: [AnyView], pageSize: CGSize) {
        self.pageSize = pageSize
        count = pages.count
        super.init(frame: NSRect(x: 0, y: 0, width: pageSize.width, height: pageSize.height * CGFloat(pages.count)))
        for (i, page) in pages.enumerated() {
            let host = NSHostingView(rootView: page.environment(\.colorScheme, .light))
            host.frame = NSRect(x: 0, y: CGFloat(i) * pageSize.height, width: pageSize.width, height: pageSize.height)
            addSubview(host)
        }
    }

    required init?(coder: NSCoder) { nil }

    override var isFlipped: Bool { true }

    override func knowsPageRange(_ range: NSRangePointer) -> Bool {
        range.pointee = NSRange(location: 1, length: count)
        return true
    }

    override func rectForPage(_ page: Int) -> NSRect {
        NSRect(x: 0, y: CGFloat(page - 1) * pageSize.height, width: pageSize.width, height: pageSize.height)
    }
}

private struct KeyPage: View {
    let keys: ChainKeys
    let relay: String

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.Space.xl) {
            Text("Clipway rescue kit")
                .font(Tokens.Typography.printTitle)
            Text("Your key, as 12 words and as a code. Keep this page somewhere safe, like your passport. Anyone who has it can read what you copy.")
                .font(Tokens.Typography.printBody)
                .foregroundStyle(Tokens.Colors.printSecondary)
                .fixedSize(horizontal: false, vertical: true)
            WordsGrid(words: keys.words, print: true)
                .padding(.vertical, Tokens.Space.s)
            HStack(alignment: .center, spacing: Tokens.Space.xl) {
                QRCodeView(text: keys.pairingCode(relay: relay), size: Tokens.Size.qrPrint)
                Text("The same key as a code: Clipway on a phone can scan it to join.")
                    .font(Tokens.Typography.printBody)
                    .foregroundStyle(Tokens.Colors.printSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Rectangle().fill(Tokens.Colors.printHairline).frame(height: Tokens.Size.hairline)
            VStack(alignment: .leading, spacing: Tokens.Space.s) {
                line("Relay", RelayAddress.host(relay))
                line("Printed", Date().formatted(Date.FormatStyle(date: .long, time: .omitted).locale(Locale(identifier: "en_US"))))
                line("App", "Clipway for Mac and Android, by Sid, sidali.dev")
            }
            Text("If you lose these 12 words and all your devices, nobody can recover your key, not even us.")
                .font(Tokens.Typography.printBody.weight(.semibold))
            Spacer()
        }
        .foregroundStyle(Tokens.Colors.printText)
        .padding(Tokens.Size.pageMargin)
        .background(Tokens.Colors.qrBackground)
    }

    private func line(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(Tokens.Colors.printSecondary).frame(width: Tokens.Size.thumbnail * 2, alignment: .leading)
            Text(value)
        }
        .font(Tokens.Typography.printBody)
    }
}

private struct TrustPage: View {
    let relay: String

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.Space.l) {
            Text("For someone you trust")
                .font(Tokens.Typography.printTitle)
            item("What this is",
                 "The owner of this kit uses Clipway to pass what they copy between their computer and their phone. Everything is encrypted with the key on the first page.")
            item("Where the words are",
                 "On the first page of this kit, and in the Keychain of their Mac. Clipway on their phone keeps them too.")
            item("Which app",
                 "Clipway, for Mac and Android, made by Sid (sidali.dev). Install it, then choose Join with 12 words on a Mac, or Type the 12 words on a phone.")
            item("Reading the history without the app",
                 "In Clipway, History, then Export, makes a ZIP file. Unzip it: history.json is plain text, readable in any text editor (or with jq). The items folder holds the images.")
            item("What the relay keeps",
                 "Nothing lasting: the relay \(RelayAddress.host(relay)) holds encrypted items for 24 hours at most, then erases them.")
            Spacer()
        }
        .font(Tokens.Typography.printBody)
        .foregroundStyle(Tokens.Colors.printText)
        .padding(Tokens.Size.pageMargin)
        .background(Tokens.Colors.qrBackground)
    }

    private func item(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: Tokens.Space.xs) {
            Text(title).font(Tokens.Typography.printBody.weight(.semibold))
            Text(text).fixedSize(horizontal: false, vertical: true)
        }
    }
}
