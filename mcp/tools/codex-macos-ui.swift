import AppKit
import ApplicationServices
import CryptoKit
import Foundation

struct Request: Decodable {
  let version: Int
  let envelope: String
  let app_bundle_id: String
  let project_label: String
  let chat_label: String
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
  let receipt: String
  let message_sha256: String
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

let input = FileHandle.standardInput.readDataToEndOfFile()
guard input.count > 0 && input.count <= 512 * 1024 else { fail("request is empty or too large") }
guard let object = try? JSONSerialization.jsonObject(with: input) as? [String: Any],
      Set(object.keys) == Set(["version", "envelope", "app_bundle_id", "project_label", "chat_label", "receipt", "message_sha256", "text"]) else {
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
      !request.project_label.isEmpty, !request.chat_label.isEmpty, !request.text.isEmpty,
      request.text.utf8.count <= 256 * 1024 else { fail("invalid fixed delivery request") }

guard AXIsProcessTrusted() else { fail("Accessibility permission is not enabled") }
let apps = NSRunningApplication.runningApplications(withBundleIdentifier: request.app_bundle_id)
guard apps.count == 1, let app = apps.first, app.isActive else { fail("Codex must be the single frontmost application") }
let application = AXUIElementCreateApplication(app.processIdentifier)
guard let window = attribute(application, kAXFocusedWindowAttribute as CFString) as! AXUIElement? else { fail("Codex has no focused window") }

func inspect() -> ([Node], [Node], [Node]) {
  let nodes = tree(window)
  let projects = nodes.filter { role($0) == kAXButtonRole && description($0) == request.project_label }
  let activeChats = nodes.filter { role($0) == kAXButtonRole && title($0) == request.chat_label && $0.depth <= 18 }
  let composers = nodes.filter { role($0) == kAXTextAreaRole && placeholder($0) == "Do anything" }
  return (projects, activeChats, composers)
}

var (projects, chats, composers) = inspect()
guard projects.count == 1 else { fail("configured project is absent or ambiguous") }
guard chats.count == 1 else { fail("configured active chat is absent or ambiguous") }
guard composers.count == 1 else { fail("composer is absent or ambiguous") }
guard value(composers[0]).isEmpty else { fail("composer is not empty") }
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
guard AXUIElementPerformAction(send[0].element, kAXPressAction as CFString) == .success else {
  _ = AXUIElementSetAttributeValue(composers[0].element, kAXValueAttribute as CFString, "" as CFTypeRef)
  fail("Send control refused AXPress")
}

let deadline = Date().addingTimeInterval(15)
var matches = 0
repeat {
  usleep(150_000)
  let nodes = tree(window)
  let seen = Set(nodes.compactMap { node -> String? in
    for candidate in [value(node), title(node), description(node)] where candidate.contains(request.receipt) { return candidate }
    return nil
  })
  matches = seen.count
} while matches == 0 && Date() < deadline

guard matches == 1 else { fail("one exact visible receipt was not observed") }
let evidence = Evidence(status: "visible", envelope: request.envelope, app_bundle_id: request.app_bundle_id,
  project_label: request.project_label, chat_label: request.chat_label, receipt: request.receipt,
  message_sha256: request.message_sha256, composer_count: 1, visible_match_count: matches)
let encoded = try JSONEncoder().encode(evidence)
FileHandle.standardOutput.write(encoded)
FileHandle.standardOutput.write(Data([0x0a]))
