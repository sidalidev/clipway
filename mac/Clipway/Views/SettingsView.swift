import ClipwayCore
import SwiftUI

/// Settings, on one page: this Mac's name, what is sent, permissions, the relay, the key.
struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.router) private var router
    @State private var name = ""
    @State private var relay = ""
    @State private var relayMessage: String?
    /// Snapshots only: fixed states instead of this Mac's.
    var permissionsPreview: (Access.State, Access.State, Access.State)?
    /// Screenshots render the whole page.
    var scrolls = true
    @State private var confirmChange = false

    var body: some View {
        Scrolling(enabled: scrolls, height: Tokens.Size.tallWindow) { page }
            .onAppear {
                name = model.deviceName
                relay = model.relay
            }
            .onDisappear { model.rename(name) }
            .alert("Change the key?", isPresented: $confirmChange) {
                Button("Change the key", role: .destructive) {
                    Task {
                        await model.changeKey()
                        router?.show(.pair)
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The relay forgets the old key and your phone stops receiving. Pair your phone again with the new code.")
            }
    }

    private var page: some View {
        @Bindable var model = model
        return VStack(alignment: .leading, spacing: Tokens.Space.l) {
            Text("Settings")
                .font(Tokens.Typography.largeTitle)
                .tracking(Tokens.Typography.largeTitleTracking)

            Card {
                LabeledContent("Name of this Mac") {
                    TextField("Name", text: $name)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: Tokens.Size.fieldWidth)
                        .onSubmit { model.rename(name) }
                }
                Text("Your phone shows it. It travels encrypted, the relay never sees it.")
                    .font(Tokens.Typography.footnote)
                    .foregroundStyle(Tokens.Colors.secondaryText)
            }

            Card {
                Toggle("Send automatically", isOn: $model.sendAutomatically)
                Toggle("Images too", isOn: $model.imagesToo)
                    .disabled(!model.sendAutomatically)
                Toggle("Show in Dock", isOn: $model.showInDock)
            }
            .toggleStyle(.clipSwitch)

            PermissionsCard(preview: permissionsPreview)

            Card {
                LabeledContent("Relay") {
                    TextField(ClipwayInfo.defaultRelay, text: $relay)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: Tokens.Size.wideFieldWidth)
                        .onSubmit(applyRelay)
                }
                if let relayMessage {
                    FieldMessage(text: relayMessage)
                } else {
                    Text(model.isDefaultRelay
                         ? "The reference relay. You can run your own: it is one small program."
                         : "Your own relay. Both devices must use the same one.")
                        .font(Tokens.Typography.footnote)
                        .foregroundStyle(Tokens.Colors.secondaryText)
                }
                HStack {
                    Button("Use this relay", action: applyRelay)
                        .buttonStyle(.secondary)
                        .disabled(relay == model.relay)
                    if !model.isDefaultRelay {
                        Button("Use the default relay") {
                            relay = ClipwayInfo.defaultRelay
                            applyRelay()
                        }
                        .buttonStyle(.quiet)
                    }
                }
            }

            Card {
                HStack(spacing: Tokens.Space.s) {
                    Button("Show the key…") { router?.show(.key) }
                        .buttonStyle(.secondary)
                    Spacer()
                    Button("Change the key…") { confirmChange = true }
                        .buttonStyle(.quiet)
                }
                .disabled(!model.isPaired)
                Text("Lost a device? Change the key: the old one stops working and your phone pairs again.")
                    .font(Tokens.Typography.footnote)
                    .foregroundStyle(Tokens.Colors.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .font(Tokens.Typography.body)
        .padding(.horizontal, Tokens.Space.xxl)
        .padding(.top, Tokens.Space.titlebar)
        .padding(.bottom, Tokens.Space.xxl)
    }

    private func applyRelay() {
        relayMessage = model.setRelay(relay)
        if relayMessage == nil {
            relay = model.relay
            Haptics.success()
        }
    }
}
