use super::*;

#[test]
fn test_apply_pre_encoding_none() {
    assert_eq!(apply_pre_encoding("test", &None), "test");
    assert_eq!(
        apply_pre_encoding("test", &Some("unknown".to_string())),
        "test"
    );
}

#[test]
fn test_apply_pre_encoding_base64() {
    assert_eq!(
        apply_pre_encoding("<script>", &Some("base64".to_string())),
        base64_encode("<script>")
    );
}

#[test]
fn test_apply_pre_encoding_2base64() {
    let expected = base64_encode(&base64_encode("<script>"));
    assert_eq!(
        apply_pre_encoding("<script>", &Some("2base64".to_string())),
        expected
    );
}

#[test]
fn test_apply_pre_encoding_2url() {
    let expected = url_encode(&url_encode("<"));
    assert_eq!(apply_pre_encoding("<", &Some("2url".to_string())), expected);
}

#[test]
fn test_apply_pre_encoding_3url() {
    let expected = url_encode(&url_encode(&url_encode("<")));
    assert_eq!(apply_pre_encoding("<", &Some("3url".to_string())), expected);
}

#[test]
fn test_pre_encoding_type_roundtrip() {
    for enc in &[
        PreEncodingType::Base64,
        PreEncodingType::DoubleBase64,
        PreEncodingType::DoubleUrl,
        PreEncodingType::TripleUrl,
    ] {
        let s = enc.as_str();
        let parsed = PreEncodingType::parse(s).unwrap();
        assert_eq!(&parsed, enc);
    }
}

#[test]
fn test_encoding_probes_cover_all_types() {
    let probes = encoding_probes();
    assert_eq!(probes.len(), 4);

    // Verify each probe encodes correctly
    let payload = "<test>";
    for (enc_type, encode_fn) in probes {
        assert_eq!(encode_fn(payload), enc_type.encode(payload));
    }
}

#[test]
fn test_multi_url_decode_probes() {
    let probes = multi_url_decode_probes();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0], (PreEncodingType::DoubleUrl, 1));
    assert_eq!(probes[1], (PreEncodingType::TripleUrl, 2));
}

#[test]
fn test_encode_consistency() {
    // Ensure apply_pre_encoding matches PreEncodingType::encode
    let payload = "<script>alert(1)</script>";
    for enc in &[
        PreEncodingType::Base64,
        PreEncodingType::DoubleBase64,
        PreEncodingType::DoubleUrl,
        PreEncodingType::TripleUrl,
    ] {
        assert_eq!(
            apply_pre_encoding(payload, &Some(enc.as_str().to_string())),
            enc.encode(payload)
        );
    }
}
