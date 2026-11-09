// Independent native decoder for synthetic Workshop golden images only.
// Never prints QR payloads. Does not use cameras or an encoder implementation.
import Foundation
import CoreImage

let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let data = try Data(contentsOf: root.appendingPathComponent("vendor/claim-qr/vectors.json"))
let vectors = try JSONSerialization.jsonObject(with: data) as! [String: Any]
let rows = vectors["valid"] as! [[String: Any]]
let context = CIContext(options: [.useSoftwareRenderer: true])
guard let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: context,
                                options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else {
    fatalError("Native QR decoder unavailable")
}
for (name, role) in [("factory-qr-light", "Link"), ("factory-qr-dark", "Core")] {
    let fixture = rows.first { row in
        let fields = row["fields"] as! [String: Any]
        return fields["environment"] as? String == "development" && fields["role"] as? String == role
    }!
    guard let image = CIImage(contentsOf: root.appendingPathComponent("test/goldens/\(name).png")) else {
        fatalError("Synthetic QR golden missing")
    }
    let messages = detector.features(in: image).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    guard messages.count == 1, messages[0] == fixture["text"] as? String else {
        fatalError("Rendered QR does not match its independent frozen fixture: \(name)")
    }
    print("\(name): native decoder matches exact 145-character \(role.uppercased()) fixture")
}
