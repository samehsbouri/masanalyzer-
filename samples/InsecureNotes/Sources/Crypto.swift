import Foundation
import CommonCrypto

// OWASP M10: ECB + DES + MD5 fallback
func legacyEncrypt(_ key: Data, _ plain: Data) -> Data {
    var data = plain
    CCCrypt(
        kCCEncrypt, kCCAlgorithmDES,
        kCCOptionECBMode | kCCOptionPKCS7Padding,
        (key as NSData).bytes, kCCKeySizeDES, nil,
        (plain as NSData).bytes, plain.count,
        &data
    )
    return data
}

func md5(_ string: String) -> String {
    // CC_MD5 removed - fixture placeholder only
    return "md5-fixture"
}
