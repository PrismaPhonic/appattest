use appattest_rs::attestation::Attestation;

fn main() {
    let app_id = "<APPLE_TEAM_ID>.<APPLE_APP_ID>"; // replace this with yours. E.g 9000738U8.auth.iphone.com
    let key_id = "G3ef9pHt9N4DxUjo/hli9tV5gGDKaD3Ue7K8cqeN/r8=";
    let challenge = "2f04f0ba-aa3a-42e4-8de1-7625c929faae";
    let base64_cbor_data = "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAzEwggMt...";

    // Decode Base64 into a buffer, then parse borrowing from it.
    let cbor = match Attestation::decode_base64(base64_cbor_data) {
        Ok(b) => b,
        Err(e) => {
            println!("Failed to decode Base64: {:?}", e);
            return;
        }
    };

    let attestation = match Attestation::from_cbor_bytes(&cbor) {
        Ok(a) => a,
        Err(e) => {
            println!("Failed to parse attestation: {:?}", e);
            return;
        }
    };

    // Supply the Apple root cert PEM bytes. Fetch once and cache.
    // static APPLE_ROOT_CERT_PEM: &[u8] = include_bytes!("Apple_App_Attestation_Root_CA.pem");
    let apple_root_cert_pem: &[u8] = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n";

    match attestation.verify_with_cert(challenge, app_id, key_id, apple_root_cert_pem) {
        Ok(_) => println!("Verification successful!"),
        Err(e) => println!("Verification failed: {:?}", e),
    }
}
