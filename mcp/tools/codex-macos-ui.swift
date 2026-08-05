import AppKit
import ApplicationServices
import CryptoKit
import Darwin
import Foundation

struct Request: Decodable {
  let version: Int
  let envelope: String
  let app_bundle_id: String
  let project_label: String
  let chat_label: String
  let thread_id: String
  let codex_state_path: String
  let receipt: String
  let message_sha256: String
  let text: String
}

struct Evidence: Encodable {
  let version = 1
  let status: String
  let envelope: String
  let app_bundle_id: String
  let project_label: String
  let chat_label: String
  let thread_id: String
  let receipt: String
  let message_sha256: String
  let project_chat_count: Int
  let active_chat_count: Int
  let composer_count: Int
  let visible_match_count: Int
}

func fail(_ message: String) -> Never {
  fputs("codex-macos-ui: \(message)\n", stderr)
  exit(1)
}

func attribute(_ element: AXUIElement, _ name: CFString) -> CFTypeRef? {
  var value: CFTypeRef?
  return AXUIElementCopyAttributeValue(element, name, &value) == .success ? value : nil
}

func text(_ element: AXUIElement, _ name: CFString) -> String {
  attribute(element, name) as? String ?? ""
}

func children(_ element: AXUIElement) -> [AXUIElement] {
  attribute(element, kAXChildrenAttribute as CFString) as? [AXUIElement] ?? []
}

struct Node { let element: AXUIElement; let depth: Int }

func tree(_ root: AXUIElement, limit: Int = 5000) -> [Node] {
  var result: [Node] = []
  var stack = [Node(element: root, depth: 0)]
  while let node = stack.popLast() {
    guard result.count < limit else { fail("accessibility tree exceeds safety bound") }
    result.append(node)
    for child in children(node.element).reversed() { stack.append(Node(element: child, depth: node.depth + 1)) }
  }
  return result
}

func role(_ node: Node) -> String { text(node.element, kAXRoleAttribute as CFString) }
func title(_ node: Node) -> String { text(node.element, kAXTitleAttribute as CFString) }
func description(_ node: Node) -> String { text(node.element, kAXDescriptionAttribute as CFString) }
func placeholder(_ node: Node) -> String { text(node.element, kAXPlaceholderValueAttribute as CFString) }
func value(_ node: Node) -> String { text(node.element, kAXValueAttribute as CFString) }

func lineage(_ start: AXUIElement, limit: Int = 80) -> [AXUIElement] {
  var result: [AXUIElement] = [], current: AXUIElement? = start
  while let item = current, result.count < limit {
    result.append(item)
    guard let parent = attribute(item, kAXParentAttribute as CFString) as! AXUIElement? else { break }
    current = parent
  }
  return result
}

func commonAncestor(_ first: AXUIElement, _ second: AXUIElement) -> (element: AXUIElement, firstDistance: Int, secondDistance: Int)? {
  let a = lineage(first), b = lineage(second)
  for (ai, left) in a.enumerated() {
    for (bi, right) in b.enumerated() where CFEqual(left, right) { return (left, ai, bi) }
  }
  return nil
}

func hasAncestorDescription(_ element: AXUIElement, _ expected: String) -> Bool {
  lineage(element).dropFirst().contains { text($0, kAXDescriptionAttribute as CFString) == expected }
}

func standardized(_ path: String) -> String { URL(fileURLWithPath: path).standardizedFileURL.path }

func selectedProjectIsBound(_ request: Request) -> Bool {
  let expectedState = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".codex/.codex-global-state.json").standardizedFileURL.path
  guard standardized(request.codex_state_path) == expectedState else { return false }
  let fd = Darwin.open(request.codex_state_path, O_RDONLY | O_NOFOLLOW)
  guard fd >= 0 else { return false }
  defer { Darwin.close(fd) }
  var info = stat()
  guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
        info.st_size >= 2, info.st_size <= 4 * 1024 * 1024,
        (info.st_mode & (S_IWGRP | S_IWOTH)) == 0 else { return false }
  var data = Data(), buffer = [UInt8](repeating: 0, count: 64 * 1024)
  while true {
    let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
    if count < 0 { return false }
    if count == 0 { break }
    data.append(buffer, count: count)
    if data.count > 4 * 1024 * 1024 { return false }
  }
  guard let state = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let selected = state["selected-project"] as? [String: Any], selected["type"] as? String == "local",
        let assignments = state["thread-project-assignments"] as? [String: Any],
        let assignment = assignments[request.thread_id] as? [String: Any], assignment["projectKind"] as? String == "local",
        let projectId = assignment["projectId"] as? String, !projectId.isEmpty,
        selected["projectId"] as? String == projectId,
        let cwd = assignment["cwd"] as? String, cwd.hasPrefix("/"),
        let projects = state["local-projects"] as? [String: Any],
        let project = projects[projectId] as? [String: Any], project["id"] as? String == projectId,
        project["name"] as? String == request.project_label,
        let roots = project["rootPaths"] as? [String], roots.map(standardized).contains(standardized(cwd)) else { return false }
  return true
}

let input = FileHandle.standardInput.readDataToEndOfFile()
guard input.count > 0 && input.count <= 512 * 1024 else { fail("request is empty or too large") }
guard let object = try? JSONSerialization.jsonObject(with: input) as? [String: Any],
      Set(object.keys) == Set(["version", "envelope", "app_bundle_id", "project_label", "chat_label", "thread_id", "codex_state_path", "receipt", "message_sha256", "text"]) else {
  fail("request contains missing or unknown fields")
}
let request: Request
do { request = try JSONDecoder().decode(Request.self, from: input) } catch { fail("request is not exact JSON") }
let digest = SHA256.hash(data: Data(request.text.utf8)).map { String(format: "%02x", $0) }.joined()
guard request.version == 1,
      request.app_bundle_id == "com.openai.codex",
      request.envelope.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
      request.receipt == "[nvoy:\(request.envelope.prefix(16))]",
      request.message_sha256 == digest,
      request.thread_id.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", options: .regularExpression) != nil,
      request.codex_state_path.hasPrefix("/"),
      !request.project_label.isEmpty, !request.chat_label.isEmpty, !request.text.isEmpty,
      request.text.utf8.count <= 256 * 1024 else { fail("invalid fixed delivery request") }

guard AXIsProcessTrusted() else { fail("Accessibility permission is not enabled") }
let apps = NSRunningApplication.runningApplications(withBundleIdentifier: request.app_bundle_id)
guard apps.count == 1, let app = apps.first else { fail("Codex must be the single running application") }
let application = AXUIElementCreateApplication(app.processIdentifier)
// Electron exposes only its native window chrome until an assistive client requests the
// Chromium accessibility tree.  The setter may return kAXErrorCannotComplete even when the
// renderer accepts it, so the expanded tree below—not the setter's return code—is the proof.
// This is Electron's documented third-party activation mechanism on macOS.
_ = AXUIElementSetAttributeValue(application, "AXManualAccessibility" as CFString, kCFBooleanTrue)
usleep(500_000)
guard let window = attribute(application, kAXFocusedWindowAttribute as CFString) as! AXUIElement? else { fail("Codex has no focused window") }

func inspect() -> ([Node], [Node], [Node], AXUIElement?) {
  let nodes = tree(window)
  let projects = nodes.filter { role($0) == kAXButtonRole && description($0) == request.project_label }
  let composers = nodes.filter { role($0) == kAXTextAreaRole && description($0) == "Do anything" }
  guard composers.count == 1 else { return (projects, [], composers, nil) }
  let named = nodes.filter { role($0) == kAXButtonRole && title($0) == request.chat_label }
  let projectChats = named.filter { hasAncestorDescription($0.element, request.project_label) }
  // Electron renders the project-qualified sidebar task and the active-chat header as separate
  // buttons. The keyless adapter has already proved from Codex's own state that this immutable
  // thread belongs to the selected project. Here the header must independently and uniquely own
  // the composer; neither a sidebar task nor a same-named inactive task can satisfy that proof.
  let active = named.compactMap { node -> (Node, AXUIElement)? in
    guard let relation = commonAncestor(node.element, composers[0].element), relation.firstDistance <= 4 else { return nil }
    return (node, relation.element)
  }
  return (projectChats, active.map { $0.0 }, composers, active.count == 1 ? active[0].1 : nil)
}

var (projectChats, chats, composers, conversationRoot) = inspect()
guard projectChats.count == 1 else { fail("configured chat is absent or ambiguous inside its project") }
guard chats.count == 1, let conversationRoot else { fail("configured chat does not uniquely own the composer") }
guard composers.count == 1 else { fail("composer is absent or ambiguous") }
guard selectedProjectIsBound(request) else { fail("configured thread is not in the selected project") }
let composerValue = value(composers[0])
let composerPlaceholder = placeholder(composers[0])
let normalizedComposer = composerValue.trimmingCharacters(in: .whitespacesAndNewlines)
let composerDescription = description(composers[0]).trimmingCharacters(in: .whitespacesAndNewlines)
let composerIsEmpty = normalizedComposer.isEmpty ||
  (!composerPlaceholder.isEmpty && composerValue == composerPlaceholder) ||
  (!composerDescription.isEmpty && normalizedComposer == composerDescription)
guard composerIsEmpty else {
  fail("composer is not empty (value \(composerValue.utf8.count) bytes; placeholder \(composerPlaceholder.utf8.count) bytes; equal \(composerValue == composerPlaceholder))")
}
guard !tree(window).contains(where: { role($0) == kAXButtonRole && description($0) == "Stop" }) else {
  fail("Codex is still producing a turn")
}

let setResult = AXUIElementSetAttributeValue(composers[0].element, kAXValueAttribute as CFString, request.text as CFTypeRef)
guard setResult == .success, value(composers[0]) == request.text else { fail("could not set the exact composer value") }

// Re-read after setting text because the Send button is rendered dynamically.
let ready = tree(window)
let send = ready.filter { role($0) == kAXButtonRole && description($0) == "Send" }
guard send.count == 1 else {
  _ = AXUIElementSetAttributeValue(composers[0].element, kAXValueAttribute as CFString, "" as CFTypeRef)
  fail("Send control is absent or ambiguous")
}
// Close the project-switch race across AX activation and composer mutation. Revalidate after
// discovering the dynamic Send control and immediately before pressing it; if selection changed,
// remove the staged text and leave no instruction behind.
guard selectedProjectIsBound(request) else {
  _ = AXUIElementSetAttributeValue(composers[0].element, kAXValueAttribute as CFString, "" as CFTypeRef)
  fail("selected project changed before send")
}
guard AXUIElementPerformAction(send[0].element, kAXPressAction as CFString) == .success else {
  _ = AXUIElementSetAttributeValue(composers[0].element, kAXValueAttribute as CFString, "" as CFTypeRef)
  fail("Send control refused AXPress")
}
// Chromium can acknowledge a background AXPress without dispatching the form.  If the exact
// staged value remains, confirm that same bound composer directly.  This is a targeted AX action,
// not a global Return keystroke, so it cannot land in another app or conversation.
usleep(300_000)
if value(composers[0]) == request.text {
  guard AXUIElementPerformAction(composers[0].element, kAXConfirmAction as CFString) == .success else {
    _ = AXUIElementSetAttributeValue(composers[0].element, kAXValueAttribute as CFString, "" as CFTypeRef)
    fail("background Send did not submit and composer refused AXConfirm")
  }
}

let deadline = Date().addingTimeInterval(15)
var matches = 0
repeat {
  usleep(150_000)
  let nodes = tree(conversationRoot)
  let seen = Set(nodes.compactMap { node -> String? in
    for candidate in [value(node), title(node), description(node)] where candidate.contains(request.receipt) { return candidate }
    return nil
  })
  matches = seen.count
} while matches == 0 && Date() < deadline

guard matches == 1 else { fail("one exact visible receipt was not observed") }
let evidence = Evidence(status: "visible", envelope: request.envelope, app_bundle_id: request.app_bundle_id,
  project_label: request.project_label, chat_label: request.chat_label, thread_id: request.thread_id, receipt: request.receipt,
  message_sha256: request.message_sha256, project_chat_count: projectChats.count,
  active_chat_count: chats.count, composer_count: 1, visible_match_count: matches)
let encoded = try JSONEncoder().encode(evidence)
FileHandle.standardOutput.write(encoded)
FileHandle.standardOutput.write(Data([0x0a]))
