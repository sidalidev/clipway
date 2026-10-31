# Assets

Everything Clipway ships that is not code, and its license.

| Asset | Where | Author | License |
|---|---|---|---|
| Bricolage Grotesque (variable: optical size, width, weight), the titles | `fonts/bricolagegrotesque/`, copies in `android/app/src/main/res/font/bricolage_grotesque.ttf` and `mac/Clipway/Fonts/` | The Bricolage Grotesque Project Authors, from github.com/google/fonts (`ofl/bricolagegrotesque`) | SIL Open Font License 1.1, [OFL.txt](fonts/bricolagegrotesque/OFL.txt), shipped in both apps |
| Figtree (variable: weight), the text | `fonts/figtree/`, copies in `android/app/src/main/res/font/figtree.ttf` and `mac/Clipway/Fonts/` | The Figtree Project Authors, from github.com/google/fonts (`ofl/figtree`) | SIL Open Font License 1.1, [OFL.txt](fonts/figtree/OFL.txt), shipped in both apps |
| App icon: two opposite arrows, cream on Lac | `android/app/src/main/res/drawable/ic_*.xml`, `mac/tools/make-icon.swift` | Sid, sidali.dev | Apache-2.0, like the apps |
| Glyphs drawn in the apps | `Tokens.kt` (`drawGlyph`), `Components.swift` (`Glyphs`) | Sid, sidali.dev | Apache-2.0 |
| BIP39 English word list | `relay/bip39-english.js`, `android/app/src/main/res/raw/bip39_english.txt`, `mac/ClipwayCore/.../BIP39English.swift` | Bitcoin BIP39 authors | MIT (BIP39) |

The Mac app also uses SF Symbols in its windows and menus, drawn by macOS and not shipped by Clipway. No sound is shipped yet.

Colors and shapes come from the charter "Miel du Champsaur": [docs/DESIGN.md](docs/DESIGN.md).
