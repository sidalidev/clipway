import AppKit
import SwiftUI

/// The fonts shipped in the app (Bricolage Grotesque and Figtree, SIL Open Font License), registered
/// for this process at launch so SwiftUI finds them by family name.
enum Fonts {
    static func register() {
        let urls = Bundle.main.urls(forResourcesWithExtension: "ttf", subdirectory: nil) ?? []
        guard !urls.isEmpty else { return }
        CTFontManagerRegisterFontURLs(urls as CFArray, .process, true, nil)
    }
}

/// The arrows of the icon, drawn on a 24 grid (stroke 2.1, round caps and joins): the menu bar
/// glyph, as a template image, so macOS tints it like every menu bar icon.
enum Glyphs {
    static let arrows: [[CGPoint]] = [
        [CGPoint(x: 5, y: 9.5), CGPoint(x: 17.5, y: 9.5)],
        [CGPoint(x: 14.5, y: 6.5), CGPoint(x: 17.5, y: 9.5), CGPoint(x: 14.5, y: 12.5)],
        [CGPoint(x: 19, y: 14.5), CGPoint(x: 6.5, y: 14.5)],
        [CGPoint(x: 9.5, y: 11.5), CGPoint(x: 6.5, y: 14.5), CGPoint(x: 9.5, y: 17.5)],
    ]

    /// Strokes the arrows in a square of `side` points, the 24 grid scaled to fit, y going down.
    static func strokeArrows(in rect: NSRect, color: NSColor, lineWidth: CGFloat) {
        let scale = rect.width / 24
        color.setStroke()
        for line in arrows {
            let path = NSBezierPath()
            path.lineWidth = lineWidth
            path.lineCapStyle = .round
            path.lineJoinStyle = .round
            for (i, p) in line.enumerated() {
                let point = NSPoint(x: rect.minX + p.x * scale, y: rect.maxY - p.y * scale)
                if i == 0 { path.move(to: point) } else { path.line(to: point) }
            }
            path.stroke()
        }
    }

    /// The menu bar icon. Dimmed when Clipway is not connected to the phone.
    static func statusIcon(dimmed: Bool, label: String) -> NSImage {
        let side = Tokens.Size.statusIcon
        let image = NSImage(size: NSSize(width: side, height: side), flipped: false) { rect in
            strokeArrows(in: rect, color: NSColor.black.withAlphaComponent(dimmed ? 0.45 : 1), lineWidth: Tokens.Radius.glyphStroke * side / 24 * 1.1)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = label
        return image
    }
}

/// Haptics on Force Touch trackpads, through the system performer (it follows the system setting).
enum Haptics {
    static func tap() { NSHapticFeedbackManager.defaultPerformer.perform(.generic, performanceTime: .now) }
    static func success() { NSHapticFeedbackManager.defaultPerformer.perform(.levelChange, performanceTime: .now) }
    static func alignment() { NSHapticFeedbackManager.defaultPerformer.perform(.alignment, performanceTime: .now) }
    /// Two quick taps: something was refused.
    static func reject() {
        tap()
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(Tokens.Motion.rejectGap * 1_000_000_000))
            tap()
        }
    }
}

/// Buttons: one filled primary action per screen, tinted secondary ones, a red one for erasing.
/// Pressed state on the first frame (spring scale), haptic on release.
struct ClipButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, destructive, plain }
    var kind: Kind = .primary
    var fullWidth = false
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        let height = kind == .primary || kind == .destructive ? Tokens.Size.primaryButton : Tokens.Size.secondaryButton
        configuration.label
            .font(kind == .primary || kind == .destructive ? Tokens.Typography.headline : Tokens.Typography.callout.weight(.medium))
            .foregroundStyle(foreground)
            .padding(.horizontal, kind == .plain ? Tokens.Space.xs : Tokens.Space.l)
            .frame(maxWidth: fullWidth ? .infinity : nil, minHeight: kind == .plain ? nil : height)
            .background(background, in: RoundedRectangle(cornerRadius: Tokens.Radius.button, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: Tokens.Radius.button, style: .continuous))
            .opacity(isEnabled ? (configuration.isPressed ? 0.85 : 1) : 0.4)
            .scaleEffect(configuration.isPressed && !reduceMotion ? Tokens.Motion.pressedScale : 1)
            .animation(reduceMotion ? nil : Tokens.Motion.press, value: configuration.isPressed)
            .onChange(of: configuration.isPressed) { _, pressed in
                if !pressed { Haptics.tap() }
            }
    }

    private var foreground: Color {
        switch kind {
        case .primary: Tokens.Colors.onAccent
        case .secondary: Tokens.Colors.onTint
        case .plain: Tokens.Colors.accent
        case .destructive: Tokens.Colors.onDanger
        }
    }

    private var background: Color {
        switch kind {
        case .primary: Tokens.Colors.accent
        case .secondary: Tokens.Colors.tint
        case .destructive: Tokens.Colors.danger
        case .plain: .clear
        }
    }
}

extension ButtonStyle where Self == ClipButtonStyle {
    static var primary: ClipButtonStyle { ClipButtonStyle(kind: .primary, fullWidth: true) }
    static var secondary: ClipButtonStyle { ClipButtonStyle(kind: .secondary) }
    static var destructive: ClipButtonStyle { ClipButtonStyle(kind: .destructive, fullWidth: true) }
    static var quiet: ClipButtonStyle { ClipButtonStyle(kind: .plain) }
}

/// A rounded group, no shadow.
struct Card<Content: View>: View {
    var padding: CGFloat = Tokens.Space.l
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: Tokens.Space.m) { content }
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Tokens.Colors.card, in: RoundedRectangle(cornerRadius: Tokens.Radius.card, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: Tokens.Radius.card, style: .continuous)
                    .strokeBorder(Tokens.Colors.hairline, lineWidth: 0.5)
            )
    }
}

struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(Tokens.Typography.footnote.weight(.semibold))
            .foregroundStyle(Tokens.Colors.secondaryText)
            .textCase(.uppercase)
            .padding(.leading, Tokens.Space.xs)
    }
}

/// The header of a window: an optional symbol, a title, one sentence.
struct ScreenHeader: View {
    var symbol: String?
    var symbolColor: Color = Tokens.Colors.accent
    /// Shows the app icon (Lac, the two arrows) instead of a symbol.
    var appIcon = false
    let title: String
    var subtitle: String?

    var body: some View {
        VStack(spacing: Tokens.Space.s) {
            if appIcon {
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .interpolation(.high)
                    .frame(width: Tokens.Size.heroIcon * 1.25, height: Tokens.Size.heroIcon * 1.25)
                    .accessibilityHidden(true)
            } else if let symbol {
                Image(systemName: symbol)
                    .font(.system(size: Tokens.Size.heroIcon * 0.6, weight: .medium))
                    .foregroundStyle(symbolColor)
                    .frame(width: Tokens.Size.heroIcon, height: Tokens.Size.heroIcon)
                    .accessibilityHidden(true)
            }
            Text(title)
                .font(Tokens.Typography.largeTitle)
                .tracking(Tokens.Typography.largeTitleTracking)
                .foregroundStyle(Tokens.Colors.text)
                .multilineTextAlignment(.center)
            if let subtitle {
                Text(subtitle)
                    .font(Tokens.Typography.body)
                    .foregroundStyle(Tokens.Colors.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity)
    }
}

/// A row of a list in a card: symbol, text, detail.
struct InfoRow: View {
    let symbol: String
    let title: String
    var detail: String?
    var symbolColor: Color = Tokens.Colors.accent

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Tokens.Space.m) {
            Image(systemName: symbol)
                .font(Tokens.Typography.body)
                .foregroundStyle(symbolColor)
                .frame(width: Tokens.Size.rowIcon * 0.7)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Tokens.Space.xxs) {
                Text(title).font(Tokens.Typography.body.weight(.medium))
                if let detail {
                    Text(detail)
                        .font(Tokens.Typography.callout)
                        .foregroundStyle(Tokens.Colors.secondaryText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The 12 words, numbered, three columns, read left to right.
struct WordsGrid: View {
    let words: [String]
    var print = false

    var body: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: Tokens.Space.m), count: 3), alignment: .leading,
                  spacing: Tokens.Space.s) {
            ForEach(Array(words.enumerated()), id: \.offset) { index, word in
                HStack(spacing: Tokens.Space.s) {
                    Text("\(index + 1)")
                        .font(Tokens.Typography.wordNumber)
                        .foregroundStyle(print ? Tokens.Colors.printSecondary : Tokens.Colors.secondaryText)
                        .frame(width: Tokens.Space.xl, alignment: .trailing)
                    Text(word)
                        .font(print ? Tokens.Typography.printWords : Tokens.Typography.words)
                        .foregroundStyle(print ? Tokens.Colors.printText : Tokens.Colors.text)
                        .lineLimit(1)
                        .fixedSize()
                        .textSelection(.disabled)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Word \(index + 1): \(word)")
            }
        }
    }
}

/// A QR code drawn locally (Core Image), dark on light, sharp at any size.
struct QRCodeView: View {
    let text: String
    var size: CGFloat = Tokens.Size.qr

    var body: some View {
        Group {
            if let image = QRCode.image(text) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
            } else {
                Color.clear
            }
        }
        .frame(width: size, height: size)
        .padding(Tokens.Space.m)
        .background(Tokens.Colors.qrBackground, in: RoundedRectangle(cornerRadius: Tokens.Radius.inner(Tokens.Radius.card, padding: Tokens.Space.s), style: .continuous))
        .accessibilityLabel("Pairing code")
    }
}

/// A short status line under a field: error in red, otherwise secondary.
struct FieldMessage: View {
    let text: String
    var isError = true
    var body: some View {
        IconText(text, symbol: isError ? "exclamationmark.circle.fill" : "checkmark.circle.fill")
            .font(Tokens.Typography.callout)
            .foregroundStyle(isError ? Tokens.Colors.danger : Tokens.Colors.success)
    }
}

/// A switch drawn the same in every window state: green when on, label on the left, spring and haptic.
struct SwitchStyle: ToggleStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: Tokens.Space.m) {
            configuration.label
            Spacer(minLength: Tokens.Space.s)
            Capsule(style: .continuous)
                .fill(configuration.isOn ? Tokens.Colors.success : Tokens.Colors.switchOff)
                .frame(width: Tokens.Size.switchWidth, height: Tokens.Size.switchHeight)
                .overlay(alignment: configuration.isOn ? .trailing : .leading) {
                    Circle()
                        .fill(Tokens.Colors.switchKnob)
                        .shadow(color: Tokens.Colors.knobShadow, radius: 1, y: 1)
                        .padding(Tokens.Space.xxs)
                }
                .animation(reduceMotion ? nil : Tokens.Motion.press, value: configuration.isOn)
        }
        .contentShape(Rectangle())
        .opacity(isEnabled ? 1 : 0.4)
        .onTapGesture {
            guard isEnabled else { return }
            configuration.isOn.toggle()
            Haptics.tap()
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
        .accessibilityAction { configuration.isOn.toggle() }
    }
}

extension ToggleStyle where Self == SwitchStyle {
    static var clipSwitch: SwitchStyle { SwitchStyle() }
}

/// A scroll view of a fixed height, or the plain content (screenshots render the whole page).
struct Scrolling<Content: View>: View {
    let enabled: Bool
    let height: CGFloat
    @ViewBuilder var content: Content

    var body: some View {
        if enabled {
            ScrollView { content }.frame(height: height)
        } else {
            content
        }
    }
}

/// A symbol and a text on one baseline. (SwiftUI's Label can loop the window layout when the
/// hosting controller sizes the window from its content.)
struct IconText: View {
    let text: String
    let symbol: String
    var symbolColor: Color?

    init(_ text: String, symbol: String, symbolColor: Color? = nil) {
        self.text = text
        self.symbol = symbol
        self.symbolColor = symbolColor
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Tokens.Space.s) {
            Image(systemName: symbol)
                .foregroundStyle(symbolColor.map { AnyShapeStyle($0) } ?? AnyShapeStyle(.foreground))
                .accessibilityHidden(true)
            Text(text)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
