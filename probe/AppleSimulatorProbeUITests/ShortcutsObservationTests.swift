import XCTest

final class ShortcutsObservationTests: XCTestCase {
    private let launchTimeout: TimeInterval = 30

    @MainActor
    func testObserveShortcutsEditorAndAutomationTabIfPresent() {
        let environment = ProcessInfo.processInfo.environment
        let directBundleID = environment["SHORTCUTS_BUNDLE_ID"]
        let prefixedBundleID = environment["TEST_RUNNER_SHORTCUTS_BUNDLE_ID"]
        if let directBundleID, let prefixedBundleID, directBundleID != prefixedBundleID {
            XCTFail("PROBE_SHORTCUTS_BUNDLE_ID_CONFLICT")
            return
        }
        guard let bundleID = directBundleID ?? prefixedBundleID, !bundleID.isEmpty else {
            XCTFail("PROBE_SHORTCUTS_BUNDLE_ID_MISSING")
            return
        }
        let shortcuts = XCUIApplication(bundleIdentifier: bundleID)
        shortcuts.launch()
        XCTAssertTrue(
            shortcuts.wait(for: .runningForeground, timeout: launchTimeout),
            "PROBE_SHORTCUTS_LAUNCH_FAILED"
        )

        attachTree(shortcuts.debugDescription, named: "shortcuts-ui-tree-initial")
        attachScreenshot(from: shortcuts, named: "shortcuts-ui-screenshot-initial")

        // Observation only: do not create, edit, import, or run a shortcut.
        let automationTab = shortcuts.tabBars.buttons["Automation"]
        let foundAutomationTab = automationTab.exists
        if foundAutomationTab {
            automationTab.tap()
            attachTree(shortcuts.debugDescription, named: "shortcuts-ui-tree-automation")
            attachScreenshot(from: shortcuts, named: "shortcuts-ui-screenshot-automation")
        }
        print("PROBE_AUTOMATION_TAB_EXISTS=\(foundAutomationTab)")
    }

    @MainActor
    private func attachTree(_ tree: String, named name: String) {
        print("PROBE_UI_BEGIN \(name)")
        print(tree)
        print("PROBE_UI_END \(name)")
        let attachment = XCTAttachment(string: tree)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    @MainActor
    private func attachScreenshot(from application: XCUIApplication, named name: String) {
        let attachment = XCTAttachment(screenshot: application.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
