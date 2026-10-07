import XCTest

final class ShortcutsObservationTests: XCTestCase {
    private let launchTimeout: TimeInterval = 30
    private let stageTimeout: TimeInterval = 8
    private let syntheticPhrase = "AUTOMATION_TEST_ONLY"

    @MainActor
    func testObserveMessageAutomationEditorWithoutRunningOrSaving() {
        let shortcuts = launchShortcutsOrFail()
        guard let shortcuts else { return }

        capture(shortcuts, stage: "initial")
        let onboarding = shortcuts.buttons.matching(NSPredicate(format: "label == %@", "Continue"))
        if onboarding.count > 0 {
            guard tapUnique(onboarding, in: shortcuts, stage: "continue-onboarding") else { return }
        }
        guard tapUnique(
            shortcuts.buttons.matching(identifier: "main.button.newshortcut"),
            in: shortcuts,
            stage: "new-shortcut"
        ) else { return }
        if !hasNamedControl("Automation", in: shortcuts) {
            guard tapNamedControl("Edit", in: shortcuts, stage: "edit-shortcut") else { return }
        }
        guard tapNamedControl("Automation", in: shortcuts, stage: "automation") else { return }
        guard tapNamedControl("Message", in: shortcuts, stage: "message") else { return }
        guard configureMessageContains(in: shortcuts) else { return }

        print("PROBE_MESSAGE_FILTER_VALUE_OBSERVED=\(syntheticPhrase)")
        print("PROBE_NO_RUN_SAVE_EXPORT_OR_NETWORK_ATTEMPTED=true")
    }

    @MainActor
    private func launchShortcutsOrFail() -> XCUIApplication? {
        let environment = ProcessInfo.processInfo.environment
        let directBundleID = environment["SHORTCUTS_BUNDLE_ID"]
        let prefixedBundleID = environment["TEST_RUNNER_SHORTCUTS_BUNDLE_ID"]
        if let directBundleID, let prefixedBundleID, directBundleID != prefixedBundleID {
            XCTFail("PROBE_SHORTCUTS_BUNDLE_ID_CONFLICT")
            return nil
        }
        guard let bundleID = directBundleID ?? prefixedBundleID, !bundleID.isEmpty else {
            XCTFail("PROBE_SHORTCUTS_BUNDLE_ID_MISSING")
            return nil
        }

        let shortcuts = XCUIApplication(bundleIdentifier: bundleID)
        shortcuts.launch()
        guard shortcuts.wait(for: .runningForeground, timeout: launchTimeout) else {
            XCTFail("PROBE_SHORTCUTS_LAUNCH_FAILED")
            return nil
        }
        return shortcuts
    }

    @MainActor
    private func hasNamedControl(_ label: String, in application: XCUIApplication) -> Bool {
        let predicate = NSPredicate(format: "label == %@", label)
        return application.buttons.matching(predicate).count + application.cells.matching(predicate).count > 0
    }

    @MainActor
    private func waitForMatches(_ first: XCUIElementQuery, _ second: XCUIElementQuery) {
        let deadline = Date().addingTimeInterval(stageTimeout)
        while first.count + second.count == 0 && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
    }

    @MainActor
    private func tapNamedControl(_ label: String, in application: XCUIApplication, stage: String) -> Bool {
        let buttons = application.buttons.matching(NSPredicate(format: "label == %@", label))
        let cells = application.cells.matching(NSPredicate(format: "label == %@", label))
        return tapExactlyOne(buttons: buttons, cells: cells, in: application, stage: stage)
    }

    @MainActor
    private func tapExactlyOne(
        buttons: XCUIElementQuery,
        cells: XCUIElementQuery,
        in application: XCUIApplication,
        stage: String
    ) -> Bool {
        let button = buttons.element(boundBy: 0)
        let cell = cells.element(boundBy: 0)
        waitForMatches(buttons, cells)

        let buttonCount = buttons.count
        let cellCount = cells.count
        let total = buttonCount + cellCount
        print("PROBE_STAGE=\(stage) BUTTONS=\(buttonCount) CELLS=\(cellCount)")
        guard total == 1 else {
            return block(at: stage, in: application, reason: "expected-one-control-found-\(total)")
        }

        let target = buttonCount == 1 ? button : cell
        guard target.isHittable else {
            return block(at: stage, in: application, reason: "control-not-hittable")
        }
        target.tap()
        settle()
        capture(application, stage: stage)
        return true
    }

    @MainActor
    private func tapUnique(_ query: XCUIElementQuery, in application: XCUIApplication, stage: String) -> Bool {
        tapExactlyOne(
            buttons: query,
            cells: application.cells.matching(NSPredicate(value: false)),
            in: application,
            stage: stage
        )
    }

    @MainActor
    private func configureMessageContains(in application: XCUIApplication) -> Bool {
        let directFields = application.textFields.matching(
            NSPredicate(format: "label == %@ OR placeholderValue == %@", "Message Contains", "Message Contains")
        )
        let directTextViews = application.textViews.matching(
            NSPredicate(format: "label == %@ OR placeholderValue == %@", "Message Contains", "Message Contains")
        )
        if directFields.count + directTextViews.count == 0 {
            let conditionContainers = application.otherElements.matching(
                identifier: "editor.action.WFMessageTrigger.WFMessageConditions"
            )
            guard conditionContainers.count == 1 else {
                return block(at: "message-condition-container", in: application, reason: "expected-one-container")
            }
            let propertySelectors = conditionContainers.element(boundBy: 0).buttons.matching(
                NSPredicate(format: "identifier == %@ AND value == %@ AND identifier != %@",
                            "enum", "Sender", "contact")
            )
            guard tapUnique(propertySelectors, in: application, stage: "message-filter-property-menu") else {
                return false
            }
            guard tapNamedControl("Message Contains", in: application, stage: "message-contains-option") else {
                return false
            }
        }

        let fields = application.textFields.matching(
            NSPredicate(format: "label == %@ OR placeholderValue == %@", "Message Contains", "Message Contains")
        )
        let textViews = application.textViews.matching(
            NSPredicate(format: "label == %@ OR placeholderValue == %@", "Message Contains", "Message Contains")
        )
        let field = fields.element(boundBy: 0)
        let textView = textViews.element(boundBy: 0)
        waitForMatches(fields, textViews)

        let fieldCount = fields.count
        let textViewCount = textViews.count
        let total = fieldCount + textViewCount
        print("PROBE_STAGE=message-contains FIELDS=\(fieldCount) TEXTVIEWS=\(textViewCount)")
        guard total == 1 else {
            return block(at: "message-contains", in: application, reason: "expected-one-exact-filter-field-found-\(total)")
        }

        let target = fieldCount == 1 ? field : textView
        guard target.isHittable else {
            return block(at: "message-contains", in: application, reason: "filter-not-hittable")
        }
        target.tap()
        target.typeText(syntheticPhrase)
        settle()
        capture(application, stage: "message-contains")
        guard target.value as? String == syntheticPhrase else {
            return block(at: "message-contains-value", in: application, reason: "filter-value-not-confirmed")
        }
        return true
    }

    @MainActor
    private func block(at stage: String, in application: XCUIApplication, reason: String) -> Bool {
        capture(application, stage: "blocked-\(stage)")
        XCTFail("PROBE_NAVIGATION_BLOCKED_AT_\(stage): \(reason)")
        return false
    }

    @MainActor
    private func settle() {
        RunLoop.current.run(until: Date().addingTimeInterval(0.5))
    }

    @MainActor
    private func capture(_ application: XCUIApplication, stage: String) {
        let tree = application.debugDescription
        print("PROBE_UI_BEGIN \(stage)")
        print(tree)
        print("PROBE_UI_END \(stage)")

        let treeAttachment = XCTAttachment(string: tree)
        treeAttachment.name = "shortcuts-ui-tree-\(stage)"
        treeAttachment.lifetime = .keepAlways
        add(treeAttachment)

        let screenshotAttachment = XCTAttachment(screenshot: application.screenshot())
        screenshotAttachment.name = "shortcuts-ui-screenshot-\(stage)"
        screenshotAttachment.lifetime = .keepAlways
        add(screenshotAttachment)
    }
}
