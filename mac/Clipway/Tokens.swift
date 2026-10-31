import AppKit
import SwiftUI

/// The one place for sizes, type, motion and colors on the Mac. Colors come from Clipway's palette
/// (Lac, the color of its icon, light and dark), never from literals in the views.
enum Tokens {
    /// 4 pt grid.
    enum Space {
        static let xxs: CGFloat = 2
        static let xs: CGFloat = 4
        static let s: CGFloat = 8
        static let m: CGFloat = 12
        static let l: CGFloat = 16
        static let xl: CGFloat = 20
        static let xxl: CGFloat = 24
        static let xxxl: CGFloat = 32
        /// Room for the window buttons above the content (transparent title bar).
        static let titlebar: CGFloat = 36
    }

    /// Concentric radii: an inner radius is the outer one minus the padding between them.
    enum Radius {
        static let card: CGFloat = 22
        /// The menu bar glyph and the icon: drawn on a 24 grid, stroke 2.1, round caps and joins.
        static let glyphStroke: CGFloat = 2.1
        static let button: CGFloat = 14
        static let field: CGFloat = 10
        static func inner(_ outer: CGFloat, padding: CGFloat) -> CGFloat { max(4, outer - padding) }
    }

    enum Size {
        static let windowWidth: CGFloat = 480
        static let wideWindowWidth: CGFloat = 560
        static let primaryButton: CGFloat = 40
        static let secondaryButton: CGFloat = 32
        static let qr: CGFloat = 200
        static let qrPrint: CGFloat = 180
        static let rowIcon: CGFloat = 28
        static let thumbnail: CGFloat = 40
        static let menuThumbnail: CGFloat = 16
        static let heroIcon: CGFloat = 56
        static let statusIcon: CGFloat = 18
        /// A4 at 72 points per inch, the rescue kit page.
        static let page = CGSize(width: 595, height: 842)
        static let pageMargin: CGFloat = 48
        static let wordsField: CGFloat = 72
        static let scrollingWindow: CGFloat = 600
        static let tallWindow: CGFloat = 640
        static let switchWidth: CGFloat = 38
        static let switchHeight: CGFloat = 22
        /// The switch at the top of the menu bar menu.
        static let menuSwitchWidth: CGFloat = 300
        static let fieldWidth: CGFloat = 220
        static let wideFieldWidth: CGFloat = 260
        static let hairline: CGFloat = 1
        /// Pair nearby: the area that holds the beacon, the code or a state, the same height in every state.
        static let nearbyStage: CGFloat = 168
        static let beacon: CGFloat = 88
        /// One digit of the 4-digit code.
        static let codeTileWidth: CGFloat = 64
        static let codeTileHeight: CGFloat = 84
    }

    /// Titles in Bricolage Grotesque 700, tracked -2 %; text in Figtree. Both SIL Open Font License,
    /// shipped in the app (Fonts/, with their licenses) and registered at launch (Fonts.register).
    enum Typography {
        static let display = "Bricolage Grotesque"
        static let text = "Figtree"
        static let largeTitle = Font.custom(display, size: 30).weight(.bold)
        static let largeTitleTracking: CGFloat = -0.6
        static let title = Font.custom(display, size: 22).weight(.bold)
        static let titleTracking: CGFloat = -0.44
        static let headline = Font.custom(text, size: 15).weight(.semibold)
        static let body = Font.custom(text, size: 14)
        static let callout = Font.custom(text, size: 13)
        static let footnote = Font.custom(text, size: 12)
        static let caption = Font.custom(text, size: 11)
        /// The 12 words: monospaced digits, so the numbered list lines up.
        static let words = Font.system(size: 15, weight: .medium, design: .rounded).monospacedDigit()
        static let wordNumber = Font.system(size: 12, weight: .regular, design: .rounded).monospacedDigit()
        static let mono = Font.system(size: 12, design: .monospaced)
        /// The 4-digit code of Pair nearby: very large, rounded, digits of equal width.
        static let codeDigit = Font.custom(display, size: 52).weight(.bold).monospacedDigit()
        static let printTitle = Font.custom(display, size: 24).weight(.bold)
        static let printBody = Font.custom(text, size: 12)
        static let printWords = Font.system(size: 16, weight: .medium, design: .rounded).monospacedDigit()
        static let menuPreviewLength = 48
    }

    enum Motion {
        static let press = Animation.spring(response: 0.25, dampingFraction: 0.6)
        static let pressedScale: CGFloat = 0.97
        static let appear = Animation.spring(response: 0.35, dampingFraction: 0.85)
        static let celebrate = Animation.spring(response: 0.45, dampingFraction: 0.55)
        /// The digits of the code land one after the other.
        static let digit = Animation.spring(response: 0.4, dampingFraction: 0.7)
        static let digitStagger: TimeInterval = 0.06
        /// The gap between the two taps of a refusal.
        static let rejectGap: TimeInterval = 0.12
        /// Undo stays available this long after a delete.
        static let undoSeconds: TimeInterval = 5
        /// The key is hidden again after this long.
        static let keyVisibleSeconds: TimeInterval = 60
        /// A status line in the menu stays this long.
        static let noteSeconds: TimeInterval = 120
    }

    /// The charter "Miel du Champsaur": Clipway is Lac, #2E7FA1 in its icon. Filled controls in light
    /// mode use the same lac deepened by 6 % (#2B7797) so cream text on it passes WCAG AA (4.69:1);
    /// dark mode uses light lac (#5BB0D3) with ink text (6.54:1). Every pair was checked by calculation.
    enum Colors {
        /// A color for each appearance, light and dark (sRGB hex).
        static func pair(_ light: UInt32, _ dark: UInt32) -> Color { Color(nsColor: ns(light, dark)) }

        static func ns(_ light: UInt32, _ dark: UInt32) -> NSColor {
            NSColor(name: nil) { appearance in
                let hex = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
                return NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                               blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
            }
        }

        /// The icon's lac, flat.
        static let lac = pair(0x2E7FA1, 0x2E7FA1)
        static let cream = pair(0xFBF7EF, 0xFBF7EF)
        static let accent = pair(0x2B7797, 0x5BB0D3)
        static let onAccent = pair(0xFBF7EF, 0x0E2430)
        static let text = pair(0x1F2A22, 0xF3EFE6)
        static let secondaryText = pair(0x4A5A4F, 0x9FB3A8)
        static let tertiaryText = pair(0x7A867D, 0x6E8378)
        static let page = pair(0xFBF7EF, 0x12201A)
        static let pageNS = ns(0xFBF7EF, 0x12201A)
        static let card = pair(0xFFFDF9, 0x1C2E26)
        static let raised = pair(0xF2ECE0, 0x263B32)
        static let hairline = pair(0xE4DCCC, 0x30463B)
        static let success = pair(0x1F7A3E, 0x7BD88F)
        static let warning = pair(0x9A5C08, 0xE9A23B)
        static let danger = pair(0xB3261E, 0xF2B8B5)
        static let onDanger = pair(0xFFFFFF, 0x601410)
        /// Secondary buttons: lac tinted, with deep lac text (6.35:1, dark 7.65:1).
        static let tint = pair(0xDEE6E4, 0x274545)
        static let onTint = pair(0x1A566F, 0xBFE3F2)
        static let dangerTint = pair(0xF9DEDC, 0x3A1F1C)
        /// Honey, the family color: the third color of illustrations.
        static let honey = pair(0xE9A23B, 0xE9A23B)
        static let switchOff = pair(0xD6CFC1, 0x3A5146)
        static let switchKnob = Color.white
        static let knobShadow = Color.black.opacity(0.2)
        /// QR codes stay dark on light in both themes, so every scanner reads them.
        static let qrBackground = Color.white
        static let printText = Color.black
        static let printSecondary = Color.black.opacity(0.6)
        static let printHairline = Color.black.opacity(0.2)
    }
}
