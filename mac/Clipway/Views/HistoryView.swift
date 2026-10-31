import ClipwayCore
import SwiftUI
import UniformTypeIdentifiers

/// The last 50 items, sent and received, newest first. Click copies back or reveals a file;
/// Delete removes one with Undo; the list ends with "That's everything".
struct HistoryView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: String?
    @State private var confirmExport = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text("History")
                    .font(Tokens.Typography.largeTitle)
                    .tracking(Tokens.Typography.largeTitleTracking)
                Spacer()
                Menu {
                    Button("Export…") { confirmExport = true }
                    Button("Clear history", role: .destructive) { model.clearHistory() }
                } label: {
                    Image(systemName: "ellipsis.circle")
                        .accessibilityLabel("More")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .disabled(model.history.isEmpty)
            }
            .padding(.horizontal, Tokens.Space.xxl)
            .padding(.top, Tokens.Space.titlebar)
            .padding(.bottom, Tokens.Space.m)

            if model.isPaired && model.link != .erasedElsewhere {
                PowerCard()
                    .padding(.horizontal, Tokens.Space.xxl)
                    .padding(.bottom, Tokens.Space.m)
            }

            if model.history.isEmpty {
                VStack(spacing: Tokens.Space.s) {
                    Image(systemName: "clock")
                        .font(Tokens.Typography.title)
                        .foregroundStyle(Tokens.Colors.secondaryText)
                    Text("Nothing yet")
                        .font(Tokens.Typography.headline)
                    Text(model.isPaired ? "Copy something on your Mac, or send from your phone." : "Pair a phone to start.")
                        .font(Tokens.Typography.callout)
                        .foregroundStyle(Tokens.Colors.secondaryText)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(selection: $selection) {
                    ForEach(model.history) { entry in
                        HistoryRow(entry: entry)
                            .tag(entry.id)
                            .contextMenu {
                                Button(entry.type == .file ? "Show in Finder" : "Copy") { model.use(entry) }
                                Button("Delete", role: .destructive) { model.delete(entry) }
                            }
                    }
                    Text("That's everything")
                        .font(Tokens.Typography.footnote)
                        .foregroundStyle(Tokens.Colors.tertiaryText)
                        .frame(maxWidth: .infinity)
                        .selectionDisabled()
                }
                .listStyle(.inset)
                .scrollContentBackground(.hidden)
                .contextMenu(forSelectionType: String.self) { _ in
                } primaryAction: { ids in
                    if let id = ids.first, let entry = model.history.first(where: { $0.id == id }) { model.use(entry) }
                }
                .onDeleteCommand {
                    if let id = selection, let entry = model.history.first(where: { $0.id == id }) { model.delete(entry) }
                }
            }

            if let undo = model.undo {
                HStack {
                    Text(undo.label)
                    Spacer()
                    Button("Undo") { model.undoLast() }
                        .buttonStyle(.secondary)
                        .keyboardShortcut("z")
                }
                .font(Tokens.Typography.callout)
                .padding(Tokens.Space.m)
                .background(Tokens.Colors.card, in: RoundedRectangle(cornerRadius: Tokens.Radius.button, style: .continuous))
                .padding(Tokens.Space.l)
                .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(Tokens.Motion.appear, value: model.undo?.id)
        .frame(height: Tokens.Size.scrollingWindow)
        .alert("Export history?", isPresented: $confirmExport) {
            Button("Export") { export() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The ZIP file is not encrypted: anyone who opens it can read your history.")
        }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Clipway history.zip"
        panel.allowedContentTypes = [.zip]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try model.exportHistory(to: url)
            Haptics.success()
        } catch {
            model.show("The export could not be saved")
        }
    }
}

struct HistoryRow: View {
    @Environment(AppModel.self) private var model
    let entry: HistoryEntry

    var body: some View {
        HStack(spacing: Tokens.Space.m) {
            icon
                .frame(width: Tokens.Size.thumbnail, height: Tokens.Size.thumbnail)
                .background(Tokens.Colors.tint, in: RoundedRectangle(cornerRadius: Tokens.Radius.field, style: .continuous))
                .clipShape(RoundedRectangle(cornerRadius: Tokens.Radius.field, style: .continuous))
            VStack(alignment: .leading, spacing: Tokens.Space.xxs) {
                Text(title)
                    .font(Tokens.Typography.body)
                    .lineLimit(2)
                    .foregroundStyle(entry.contentRemoved ? Tokens.Colors.secondaryText : Tokens.Colors.text)
                Text(subtitle)
                    .font(Tokens.Typography.footnote)
                    .foregroundStyle(Tokens.Colors.secondaryText)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, Tokens.Space.xs)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder
    private var icon: some View {
        if entry.type == .image, let thumb = model.thumbnail(entry, size: Tokens.Size.thumbnail * 2) {
            Image(nsImage: thumb)
                .resizable()
                .scaledToFill()
        } else {
            Image(systemName: entry.type == .file ? "doc" : entry.type == .image ? "photo" : "text.alignleft")
                .foregroundStyle(Tokens.Colors.accent)
        }
    }

    private var title: String {
        if entry.contentRemoved { return "Content removed to save space" }
        switch entry.type {
        case .text: return entry.preview
        case .image: return entry.name ?? "Image"
        case .file: return entry.name ?? "File"
        case .hello, .offer, .reply: return entry.device
        }
    }

    private var subtitle: String {
        let when = Date(timeIntervalSince1970: Double(entry.ts) / 1000)
        let time = when.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened).locale(Locale(identifier: "en_US")))
        let size = entry.type == .text ? "" : ", \(StatusItemController.bytes(entry.size))"
        if entry.direction == .received { return "From \(entry.device), \(time)\(size)" }
        let status: String
        switch entry.status {
        case .sending: status = "Sending"
        case .sent: status = "Sent"
        case .waiting: status = "Waiting for your phone"
        case .delivered: status = "Delivered"
        case .failed: status = "Not sent"
        case .unreachable: status = "Not sent: not on the same network"
        case nil: status = "Sent"
        }
        return "\(status), \(time)\(size)"
    }
}

/// The master switch, in the main window: Clipway on, or paused, with one sentence on what stops.
/// The same one as at the top of the menu bar menu.
struct PowerCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let on = Binding(get: { !model.paused }, set: { model.setPaused(!$0) })
        Card {
            Toggle(isOn: on) {
                HStack(spacing: Tokens.Space.s) {
                    Text("Clipway")
                        .font(Tokens.Typography.headline)
                    Spacer(minLength: Tokens.Space.s)
                    Text(model.powerLabel)
                        .font(Tokens.Typography.callout)
                        .foregroundStyle(model.paused ? Tokens.Colors.secondaryText : Tokens.Colors.success)
                }
            }
            .toggleStyle(.clipSwitch)
            Text(model.powerDetail)
                .font(Tokens.Typography.footnote)
                .foregroundStyle(Tokens.Colors.secondaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Clipway")
        .accessibilityValue(model.powerLabel)
        .accessibilityHint(model.powerDetail)
        .accessibilityAddTraits(.isToggle)
        .accessibilityAction {
            model.setPaused(!model.paused)
            Haptics.tap()
        }
    }
}
