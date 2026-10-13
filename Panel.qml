import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Ui
import qs.Commons
import "Model.js" as Model

// Ente Auth codes in the bar. Clicking the icon opens a
// launcher-style panel: the search field has focus straight away, typing
// filters, Enter copies. Styled like the stock panels:
// every colour comes from the theme, and the chrome is the shared qs.Ui kit.
//
// Keys (handled by the search field; PanelKeyCatcher is not used because it
// eats j/k/h/l/x/space before they reach a text field):
//   Up/Down, Ctrl+J/K  move         Enter        copy current code
//   PgUp/PgDn          move by 5    Shift+Enter  copy next code
//   Tab/Shift+Tab      next panel   Esc          close
Panel {
  id: root

  moduleName: "lcd1232.ente-auth"
  ipcTarget: "lcd1232.ente-auth"
  manageIpc: false

  readonly property string ff: bar ? bar.fontFamily : Style.font.family
  readonly property color dimForeground: Qt.darker(barForeground, 1.4)
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property bool healthy: svc.ok

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  property string searchText: ""
  property int selectedIndex: 0
  property string copiedKey: ""
  property real nowSec: Date.now() / 1000

  // Clipboard bookkeeping (see copyCode / clearClipboardIfOurs).
  property string _clipboardCode: ""
  property string _pendingCopy: ""
  property string _pendingCheck: ""
  property string _checkingCode: ""

  readonly property string pluginDir: {
    var s = String(Qt.resolvedUrl("."))
    if (s.indexOf("file://") === 0) s = s.substring(7)
    return s
  }
  readonly property string clipcheckPath: {
    var base = pluginDir
    if (base.length && base.charAt(base.length - 1) !== "/") base += "/"
    return base + "bin/enteauth-clipcheck"
  }

  function boolSetting(name, fallback) {
    var v = settings ? settings[name] : undefined
    if (v === undefined || v === null || v === "") return fallback
    return v === true || v === "true"
  }
  readonly property bool closeOnCopy: boolSetting("closeOnCopy", true)
  readonly property bool notifyOnCopy: boolSetting("notifyOnCopy", true)
  readonly property int clipboardClearSec: {
    var raw = settings ? settings.clipboardClearSec : undefined
    var n = parseInt(String(raw === undefined || raw === null ? 20 : raw), 10)
    if (!isFinite(n) || n < 0) n = 20
    return Math.min(n, 600)
  }

  Component.onCompleted: svc.check()

  // ---------- List ----------
  readonly property var rows: Model.rankEntries(svc.entries, searchText)
  readonly property var selectedRow: rows.length ? rows[Math.min(selectedIndex, rows.length - 1)] : null
  readonly property var selectedState: selectedRow ? Model.codeState(selectedRow.entry, nowSec) : null

  // Setup or read error: nothing to search, so only the message is shown.
  readonly property bool setupError: !svc.ok && !!svc.error
  onSetupErrorChanged: if (setupError && opened) errorKeys.forceActiveFocus()

  // Install command for a missing app or package, shown with a Copy button.
  readonly property string installCommand: (!svc.ok && svc.error) ? Model.installCommand(svc.error) : ""
  property bool installCopied: false

  function copyInstallCommand() {
    if (!Model.canCopyCommand(installCommand) || copyProcess.running) return
    // Not a secret, so no --sensitive; still on stdin like the codes.
    _pendingCopy = installCommand
    copyProcess.command = ["wl-copy"]
    copyProcess.stdinEnabled = true
    copyProcess.running = true
    installCopied = true
    installCopiedTimer.restart()
  }

  Timer {
    id: installCopiedTimer
    interval: 2000
    onTriggered: root.installCopied = false
  }

  readonly property string statusLine: Model.statusHint({
    refreshing: svc.refreshing, ok: svc.ok, error: svc.error, total: svc.entries.length,
    shown: rows.length, query: searchText, skipped: svc.skipped
  })

  onSearchTextChanged: {
    selectedIndex = 0
    listFlick.contentY = 0
  }

  function refresh() { svc.refresh() }

  function moveCursor(dy) {
    if (rows.length === 0) return
    selectedIndex = Math.max(0, Math.min(rows.length - 1, selectedIndex + dy))
    scrollCursorIntoView()
  }

  // Keyboard moves only: hover also sets selectedIndex, and scrolling under a
  // hovering mouse would make the list lurch.
  function scrollCursorIntoView() {
    Qt.callLater(function() {
      var item = entryRepeater.itemAt(selectedIndex)
      if (!item) return
      var top = item.y
      var bottom = top + item.height
      var maxY = Math.max(0, listFlick.contentHeight - listFlick.height)
      if (top < listFlick.contentY)
        listFlick.contentY = Math.max(0, top)
      else if (bottom > listFlick.contentY + listFlick.height)
        listFlick.contentY = Math.min(maxY, bottom - listFlick.height)
    })
  }

  function copySelected(useNext) {
    var row = selectedRow
    if (!row) return
    var st = Model.codeState(row.entry, nowSec)
    copyCode(row.entry, useNext ? st.next : st.code, useNext)
  }

  function copyCode(entry, code, isNext) {
    code = String(code || "").replace(/\s+/g, "")
    if (!/^[0-9]{1,10}$/.test(code)) return
    copiedKey = Model.entryKey(entry)
    // --sensitive asks clipboard managers that honour the hint not to keep it.
    // The code goes in on stdin, never on argv: wl-copy stays running in the
    // background and its command line is visible to every user via ps/procfs.
    _pendingCopy = code
    copyProcess.command = ["wl-copy", "--sensitive"]
    copyProcess.stdinEnabled = true
    copyProcess.running = true
    _clipboardCode = code
    if (clipboardClearSec > 0) clipboardClearTimer.restart()
    if (notifyOnCopy) {
      var label = String(entry.issuer || "Account")
      if (entry.account) label += " · " + String(entry.account)
      Quickshell.execDetached(["notify-send", "-a", "Authenticator", "-t", "2000",
        isNext ? "Copied next code" : "Copied code", label])
    }
    if (closeOnCopy) closeAfterCopy.restart()
    else copiedTimer.restart()
  }

  // Clear the clipboard after clipboardClearSec, but only if it still holds
  // the code we put there. The clipboard is never read into this long-lived
  // process: bin/enteauth-clipcheck compares it and prints match/nomatch.
  function clearClipboardIfOurs() {
    if (!_clipboardCode || clipboardCheck.running) return
    if (!/^[0-9]{1,10}$/.test(_clipboardCode)) { _clipboardCode = ""; return }
    if (!clipcheckPath.endsWith("/bin/enteauth-clipcheck")) return
    _pendingCheck = _clipboardCode
    _checkingCode = _clipboardCode
    clipboardCheck.command = ["/bin/sh", clipcheckPath]
    clipboardCheck.stdinEnabled = true
    clipboardCheck.running = true
  }

  onOpenedChanged: {
    if (opened) {
      searchText = ""
      searchField.text = ""
      selectedIndex = 0
      listFlick.contentY = 0
      nowSec = Date.now() / 1000
      refresh()
    } else {
      closeAfterCopy.stop()
      copiedKey = ""
      svc.forget()
    }
  }

  Service {
    id: svc
    settings: root.settings
    pluginDir: root.pluginDir
  }

  // One clock for every row while open. The helper only re-runs when the
  // code window runs low (Service.tick).
  Timer {
    interval: 1000
    repeat: true
    running: root.opened
    onTriggered: {
      root.nowSec = Date.now() / 1000
      svc.tick(root.nowSec)
    }
  }

  Timer {
    id: copiedTimer
    interval: 1200
    onTriggered: root.copiedKey = ""
  }

  // Short delay so the copied row flashes before the panel goes.
  Timer {
    id: closeAfterCopy
    interval: 180
    onTriggered: root.close()
  }

  Process {
    id: copyProcess
    running: false
    command: []
    stdinEnabled: false
    onStarted: {
      write(root._pendingCopy)
      root._pendingCopy = ""
      stdinEnabled = false // closes stdin -> EOF, wl-copy takes the data
    }
    onExited: { root._pendingCopy = ""; stdinEnabled = false }
  }

  Timer {
    id: clipboardClearTimer
    interval: Math.max(1, root.clipboardClearSec) * 1000
    onTriggered: root.clearClipboardIfOurs()
  }

  Process {
    id: clipboardCheck
    running: false
    command: []
    stdinEnabled: false
    stdout: StdioCollector {
      id: clipboardCheckOut
      waitForEnd: true
    }
    onStarted: {
      write(root._pendingCheck)
      root._pendingCheck = ""
      stdinEnabled = false
    }
    onExited: {
      root._pendingCheck = ""
      stdinEnabled = false
      var current = root._clipboardCode === root._checkingCode
      if (current && clipboardCheckOut.text === "match\n") {
        clearProcess.command = ["wl-copy", "--clear"]
        clearProcess.running = true
      }
      if (current) root._clipboardCode = ""
      root._checkingCode = ""
    }
  }

  Timer {
    interval: 10000
    running: clipboardCheck.running
    onTriggered: clipboardCheck.running = false
  }

  Process { id: clearProcess; running: false; command: [] }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { root.refresh(); return "ok" }
    function clearClipboard(): string { root.clearClipboardIfOurs(); return "ok" }
  }

  // ---------- Bar icon ----------
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    tooltipText: "Authenticator"
    iconComponent: Component {
      Item {
        EnteAuthIcon {
          anchors.centerIn: parent
          iconSize: Style.space(12)
          color: root.healthy ? root.barForeground : root.dimForeground
          iconOpacity: root.healthy ? 1.0 : 0.6
        }
      }
    }
    onPressed: function(b) {
      if (b === Qt.RightButton) root.refresh()
      else root.toggle()
    }
  }

  // One account: issuer and account on the left, code and countdown on the
  // right. Same row chrome as the network list (CursorSurface).
  component AccountRow: CursorSurface {
    id: row

    required property var modelData
    required property int index
    readonly property var entry: modelData.entry
    readonly property var st: Model.codeState(entry, root.nowSec)
    readonly property bool ending: st.remaining <= 5

    implicitHeight: rowBody.implicitHeight + Style.spacing.rowPaddingX
    hasCursor: index === root.selectedIndex
    current: root.copiedKey === Model.entryKey(entry)
    foreground: root.barForeground

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.LeftButton
      cursorShape: Qt.PointingHandCursor
      onContainsMouseChanged: if (containsMouse) root.selectedIndex = row.index
      onClicked: {
        root.selectedIndex = row.index
        root.copyCode(row.entry, row.st.code, false)
      }
    }

    Item {
      id: rowBody
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(10)
      anchors.rightMargin: Style.space(10)
      implicitHeight: Math.max(labels.implicitHeight, codeColumn.implicitHeight)

      Column {
        id: labels
        anchors.left: parent.left
        anchors.right: codeColumn.left
        anchors.rightMargin: Style.space(10)
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(1)

        Text {
          width: parent.width
          // Labels come from Ente data and are untrusted: never render them as rich text.
          textFormat: Text.PlainText
          text: (row.modelData.pinned ? "󰐃 " : "") + String(row.entry.issuer || "Account")
          color: root.barForeground
          font.family: root.ff
          font.pixelSize: Style.font.bodySmall
          elide: Text.ElideRight
        }

        Text {
          width: parent.width
          visible: text.length > 0
          textFormat: Text.PlainText
          text: String(row.entry.account || "")
          color: root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }
      }

      Column {
        id: codeColumn
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(3)

        Text {
          anchors.right: parent.right
          textFormat: Text.PlainText
          text: row.st.stale ? "··· ···" : Model.formatCode(row.st.code)
          color: row.ending ? root.urgent : root.barForeground
          font.family: root.ff
          font.pixelSize: Style.font.subtitle
        }

        // Countdown, drawn like sysmon's core bars.
        Item {
          anchors.right: parent.right
          width: Style.space(52)
          height: Style.space(2)

          Rectangle {
            anchors.fill: parent
            radius: height / 2
            color: root.barForeground
            opacity: 0.06
          }

          Rectangle {
            anchors.right: parent.right
            height: parent.height
            radius: height / 2
            width: parent.width * Math.max(0, Math.min(1, row.st.remaining / row.st.period))
            color: row.ending ? root.urgent : Color.accent
            opacity: 0.85
          }
        }
      }
    }
  }

  // ---------- Panel ----------
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: root.setupError ? errorKeys : searchField
    contentWidth: panel.fittedContentWidth(Style.space(360))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(560))

    // Takes keyboard focus while the search field is hidden (setup errors),
    // so Esc and Tab still work.
    Item {
      id: errorKeys
      width: 0
      height: 0
      Keys.onPressed: function(event) {
        var shift = event.modifiers & Qt.ShiftModifier
        if (event.key === Qt.Key_Escape) root.close()
        else if (event.key === Qt.Key_Tab || event.key === Qt.Key_Backtab)
          root.switchPanel(shift || event.key === Qt.Key_Backtab ? -1 : 1)
        else return
        event.accepted = true
      }
    }

    Column {
      id: column
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.top: parent.top
      spacing: Style.space(14)

      TextField {
        id: searchField
        width: parent.width
        visible: !root.setupError
        placeholderText: "Search accounts"
        font.family: root.ff
        font.pixelSize: Style.font.body
        foreground: root.barForeground
        onTextChanged: root.searchText = text

        Keys.onPressed: function(event) {
          var ctrl = event.modifiers & Qt.ControlModifier
          var shift = event.modifiers & Qt.ShiftModifier
          if (event.key === Qt.Key_Escape) {
            root.close()
          } else if (event.key === Qt.Key_Down || (ctrl && event.key === Qt.Key_J)) {
            root.moveCursor(1)
          } else if (event.key === Qt.Key_Up || (ctrl && event.key === Qt.Key_K)) {
            root.moveCursor(-1)
          } else if (event.key === Qt.Key_PageDown) {
            root.moveCursor(5)
          } else if (event.key === Qt.Key_PageUp) {
            root.moveCursor(-5)
          } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            root.copySelected(!!shift)
          } else if (event.key === Qt.Key_Tab || event.key === Qt.Key_Backtab) {
            root.switchPanel(shift || event.key === Qt.Key_Backtab ? -1 : 1)
          } else {
            return
          }
          event.accepted = true
        }
      }

      PanelSeparator { id: separatorTop; visible: !root.setupError; foreground: root.barForeground }

      // Setup or read error: what went wrong, what to do, and the command
      // that fixes it (if any), in place of the list.
      Column {
        id: errorView
        width: parent.width
        visible: root.setupError
        spacing: Style.space(10)

        Text {
          width: parent.width
          text: root.setupError ? Model.errorHint(svc.error) : ""
          textFormat: Text.PlainText
          color: root.urgent
          font.family: root.ff
          font.pixelSize: Style.font.body
          font.bold: true
          wrapMode: Text.WordWrap
        }

        Text {
          width: parent.width
          visible: text.length > 0
          text: root.setupError ? Model.errorDetail(svc.error) : ""
          textFormat: Text.PlainText
          color: root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // The command as a code block, with a copy button like a code
        // snippet on GitHub.
        Rectangle {
          id: commandBlock
          width: parent.width
          visible: root.installCommand.length > 0
          implicitHeight: Math.max(commandText.implicitHeight, copyCommandButton.visible ? copyCommandButton.height : 0)
            + Style.space(8) * 2
          radius: Style.cornerRadius
          color: Style.normalFillFor(root.barForeground, root.barForeground, root.urgent)
          border.width: Style.normalBorderWidth
          border.color: Style.normalBorderFor(root.barForeground, root.barForeground, root.urgent)

          // Selectable, so it can still be copied by hand without wl-clipboard.
          TextEdit {
            id: commandText
            anchors.left: parent.left
            anchors.leftMargin: Style.space(10)
            anchors.verticalCenter: parent.verticalCenter
            width: parent.width - Style.space(10) * 2
              - (copyCommandButton.visible ? copyCommandButton.width + Style.space(6) : 0)
            readOnly: true
            selectByMouse: true
            textFormat: TextEdit.PlainText
            wrapMode: TextEdit.WrapAtWordBoundaryOrAnywhere
            text: root.installCommand
            color: root.barForeground
            font.family: root.ff
            font.pixelSize: Style.font.bodySmall
          }

          PanelActionButton {
            id: copyCommandButton
            anchors.right: parent.right
            anchors.rightMargin: Style.space(4)
            anchors.verticalCenter: parent.verticalCenter
            visible: Model.canCopyCommand(root.installCommand)
            iconText: root.installCopied ? "󰄬" : "󰆏"
            tooltipText: root.installCopied ? "Copied" : "Copy"
            foreground: root.installCopied ? root.barForeground : root.dimForeground
            hoverColor: root.barForeground
            fontFamily: root.ff
            fontSize: Style.font.iconSmall
            onClicked: root.copyInstallCommand()
          }
        }
      }

      Column {
        id: listSection
        width: parent.width
        visible: !root.setupError
        spacing: Style.space(6)

        Item {
          id: listHeader
          width: parent.width
          visible: !root.setupError
          implicitHeight: sectionTitle.implicitHeight

          PanelSectionHeader {
            id: sectionTitle
            anchors.left: parent.left
            text: root.searchText.length ? "RESULTS" : "ACCOUNTS"
            foreground: root.barForeground
            fontFamily: root.ff
          }

          PanelSectionHeader {
            anchors.right: parent.right
            visible: root.rows.length > 0
            text: String(root.rows.length)
            foreground: root.barForeground
            fontFamily: root.ff
          }
        }

        Text {
          id: statusText
          width: parent.width
          visible: text.length > 0 && !root.setupError
          text: root.statusLine
          textFormat: Text.PlainText
          color: (!svc.ok && svc.error) ? root.urgent : root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // Only the list scrolls. A Flickable rather than a ListView: the model
        // is rebuilt on every refresh and a ListView would jump to the top.
        Flickable {
          id: listFlick
          width: parent.width
          visible: root.rows.length > 0
          readonly property real maxHeight: {
            var cardCap = panel.availableCardHeight > 0
              ? Math.min(Style.space(560), panel.availableCardHeight) : Style.space(560)
            var fixed = searchField.height + separatorTop.height + separatorA.height
              + listHeader.height + footer.height
              + (statusText.visible ? statusText.height + listSection.spacing : 0)
              + column.spacing * 4 + listSection.spacing
            return Math.max(Style.space(44), cardCap - panel.verticalContentInset - fixed)
          }
          height: visible ? Math.min(listColumn.implicitHeight, maxHeight) : 0
          contentWidth: width
          contentHeight: listColumn.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          flickableDirection: Flickable.VerticalFlick
          interactive: contentHeight > height
          ScrollBar.vertical: ScrollBar { policy: listFlick.interactive ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff }

          Column {
            id: listColumn
            // Room for the scrollbar so it does not cover the codes.
            width: listFlick.width - (listFlick.interactive ? Style.space(10) : 0)
            spacing: Style.space(2)

            Repeater {
              id: entryRepeater
              model: root.rows
              delegate: AccountRow { width: listColumn.width }
            }
          }
        }
      }

      PanelSeparator { id: separatorA; visible: root.rows.length > 0; foreground: root.barForeground }

      // Next code for the selected account, and the keys.
      Item {
        id: footer
        width: parent.width
        // Copy hints only make sense when there is something to copy.
        visible: root.rows.length > 0
        implicitHeight: Math.max(nextText.implicitHeight, hintText.implicitHeight)

        Text {
          id: nextText
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          textFormat: Text.PlainText
          text: root.selectedState && root.selectedState.next
            ? "󰒭  " + Model.formatCode(root.selectedState.next) : ""
          color: root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.caption
        }

        Text {
          id: hintText
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          text: "↵ copy   ⇧↵ next"
          color: root.dimForeground
          font.family: root.ff
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
