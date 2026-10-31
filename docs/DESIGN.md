# Design

Clipway follows the charter of Sid's apps, "Miel du Champsaur": every app has its own color, the same in its icon and in the app, light and dark. Flat (no gradient, no shine), everything rounded (no hard corner, no point).

## Colors

| Role | Light | Dark |
|---|---|---|
| Clipway, Lac (icon background) | `#2E7FA1` | `#2E7FA1` |
| Filled controls, links, glyphs | `#2B7797` (the same lac, 6 % deeper, for AA text) | `#5BB0D3` (light lac) |
| Text on filled controls | `#FBF7EF` cream | `#0E2430` |
| Page | `#FBF7EF` | `#12201A` |
| Cards | `#FFFDF9` | `#1C2E26` |
| Text | `#1F2A22` fir ink | `#F3EFE6` |
| Secondary text | `#4A5A4F` | `#9FB3A8` |
| Tinted secondary buttons | `#DEE6E4`, text `#1A566F` | `#274545`, text `#BFE3F2` |
| Third color of illustrations | `#E9A23B` honey, ink on it | same |
| Switches (semantic green) | `#1F7A3E` | `#7BD88F` |
| Destructive (semantic red) | `#B3261E` | `#F2B8B5` |

Android: a fixed Material 3 scheme built from these (`Tokens.kt`), never the wallpaper's colors. Mac: the same values (`Tokens.swift`), applied to every window instead of the system accent color.

## Contrast (WCAG 2.1, computed)

AA asks 4.5:1 for text and 3:1 for large text and graphics.

| Mode | What | Colors | Ratio |
|---|---|---|---|
| Light | Text on page | `#1F2A22` on `#FBF7EF` | 13.91:1 |
| Light | Text on card | `#1F2A22` on `#FFFDF9` | 14.63:1 |
| Light | Secondary text on page | `#4A5A4F` on `#FBF7EF` | 6.86:1 |
| Light | Secondary text on card | `#4A5A4F` on `#FFFDF9` | 7.21:1 |
| Light | Cream on filled lac (buttons) | `#FBF7EF` on `#2B7797` | 4.69:1 |
| Light | Lac text on card | `#2B7797` on `#FFFDF9` | 4.94:1 |
| Light | Tinted button text | `#1A566F` on `#DEE6E4` | 6.35:1 |
| Light | Badge | `#123F54` on `#D5E9F2` | 8.99:1 |
| Light | White thumb on green switch | `#FFFFFF` on `#1F7A3E` | 5.37:1 |
| Light | Danger on card | `#B3261E` on `#FFFDF9` | 6.43:1 |
| Light | Warning on card | `#9A5C08` on `#FFFDF9` | 5.29:1 |
| Light | Ink on honey | `#1F2A22` on `#E9A23B` | 6.86:1 |
| Icon | Cream drawing on lac #2E7FA1 (graphic, 3:1 needed) | `#FBF7EF` on `#2E7FA1` | 4.21:1 |
| Dark | Text on page | `#F3EFE6` on `#12201A` | 14.67:1 |
| Dark | Text on card | `#F3EFE6` on `#1C2E26` | 12.46:1 |
| Dark | Secondary text on page | `#9FB3A8` on `#12201A` | 7.61:1 |
| Dark | Secondary text on card | `#9FB3A8` on `#1C2E26` | 6.46:1 |
| Dark | Ink on filled light lac (buttons) | `#0E2430` on `#5BB0D3` | 6.54:1 |
| Dark | Light lac text on card | `#5BB0D3` on `#1C2E26` | 5.85:1 |
| Dark | Tinted button text | `#BFE3F2` on `#274545` | 7.65:1 |
| Dark | Badge | `#D4EEF8` on `#1F4A5C` | 7.93:1 |
| Dark | Dark thumb on green switch | `#00391A` on `#7BD88F` | 7.54:1 |
| Dark | Danger on card | `#F2B8B5` on `#1C2E26` | 8.38:1 |
| Dark | Warning on card | `#E9A23B` on `#1C2E26` | 6.60:1 |

Cream on the icon's lac (#2E7FA1) is 4.21:1: enough for the icon's drawing, not for text. That is why filled buttons use #2B7797 in light mode.

## Type

Titles: Bricolage Grotesque 700, tracked -2 %. Text: Figtree. Both under the SIL Open Font License ([ASSETS.md](../ASSETS.md)), shipped in the apps. Android sizes are in sp, so the phone's text size setting applies.

## Shapes

Cards: radius 24 on Android, 22 on the Mac (macOS windows). Buttons: radius 14 or pills. Icons and glyphs: a 24 grid, stroke 2.1, round caps and round joins. App icon: the lac square (radius about 30 % on Android launchers, macOS corners on the Mac) and two opposite arrows in cream: `M5 9.5h12.5`, `M14.5 6.5l3 3-3 3`, `M19 14.5H6.5`, `M9.5 11.5l-3 3 3 3`.
