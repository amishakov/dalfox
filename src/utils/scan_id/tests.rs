use super::*;

#[test]
fn test_make_scan_id_shape() {
    let id = make_scan_id_with_nonce("https://example.com", 42);
    assert_eq!(id.len(), 64);
    assert!(
        id.chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_lowercase() || c.is_ascii_digit()))
    );
}

#[test]
fn test_make_scan_id_uniqueness_with_different_nonces() {
    let a = make_scan_id_with_nonce("seed", 1);
    let b = make_scan_id_with_nonce("seed", 2);
    assert_ne!(a, b);
}

#[test]
fn test_short_scan_id() {
    assert_eq!(short_scan_id("abcdef1234"), "abcdef1");
    assert_eq!(short_scan_id("abc"), "abc");
    let id = make_scan_id_with_nonce("seed", 999);
    assert_eq!(short_scan_id(&id).len(), 7);
}
