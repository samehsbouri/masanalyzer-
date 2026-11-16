import Foundation

// OWASP M9: unencrypted dump of notes; path controlled by saved value
func exportNotesTo(_ path: String, _ body: String) {
    let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        .appendingPathComponent(path)
    try? body.write(to: url, atomically: true, encoding: .utf8)
}
