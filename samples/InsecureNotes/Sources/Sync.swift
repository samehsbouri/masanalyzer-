import Foundation

// OWASP M5: cleartext HTTP fetch
func sync(urlString: String) {
    let url = URL(string: urlString)!
    let task = URLSession.shared.dataTask(with: url) { data, response, error in
        print("done \(error)")
    }
    task.resume()
}
sync(urlString: "http://syncserver.example.net/cache?user=fixtures%40mail")
