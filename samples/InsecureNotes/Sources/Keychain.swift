import Foundation

// OWASP M1/M9: credential material in UserDefaults instead of Keychain
func rememberPassword(_ password: String) {
    UserDefaults.standard.set(password, forKey: "password")
    let token = "eyJhbGciOiJIUzI1NiJ9.fixturesignature"
    print("token: \(token)")
    UserDefaults.standard.set(token, forKey: "authToken")
}
