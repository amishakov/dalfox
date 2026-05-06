use super::*;

#[test]
fn test_short_id_returns_8_chars() {
    let id = short_id("test");
    assert_eq!(id.len(), 8, "short_id should be exactly 8 chars");
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_open_marker_prefix_and_length() {
    let m = open_marker();
    assert!(m.starts_with("dlx"), "open_marker should start with 'dlx'");
    assert_eq!(m.len(), 11, "dlx + 8 hex chars = 11");
}

#[test]
fn test_close_marker_prefix_and_length() {
    let m = close_marker();
    assert!(m.starts_with("xld"), "close_marker should start with 'xld'");
    assert_eq!(m.len(), 11, "xld + 8 hex chars = 11");
}

#[test]
fn test_class_marker_prefix_and_length() {
    let m = class_marker();
    assert!(m.starts_with("dlx"), "class_marker should start with 'dlx'");
    assert_eq!(m.len(), 11);
}

#[test]
fn test_id_marker_prefix_and_length() {
    let m = id_marker();
    assert!(m.starts_with("dlx"), "id_marker should start with 'dlx'");
    assert_eq!(m.len(), 11);
}

#[test]
fn test_markers_are_distinct() {
    let open = open_marker();
    let close = close_marker();
    let class = class_marker();
    let id = id_marker();
    assert_ne!(open, close);
    assert_ne!(open, class);
    assert_ne!(open, id);
    assert_ne!(close, class);
    assert_ne!(close, id);
    assert_ne!(class, id);
}

#[test]
fn test_markers_are_stable() {
    // OnceLock guarantees same value on repeated calls
    let a = open_marker();
    let b = open_marker();
    assert_eq!(a, b);
    assert!(std::ptr::eq(a, b), "should return same &'static str");
}

#[test]
fn test_markers_are_css_safe() {
    // Class and id markers must be valid CSS identifiers (alphanumeric)
    for m in [class_marker(), id_marker()] {
        assert!(
            m.chars().all(|c| c.is_ascii_alphanumeric()),
            "marker '{}' must be alphanumeric for CSS selector usage",
            m
        );
    }
}

#[test]
fn test_inner_marker_distinct_prefix() {
    let inner = inner_marker();
    assert!(inner.starts_with("dlxmid"));
    assert!(!inner.contains(open_marker()));
    assert!(!inner.contains(close_marker()));
    // and vice-versa: open/close must not contain inner
    assert!(!open_marker().contains(inner));
    assert!(!close_marker().contains(inner));
}

#[test]
fn test_bracketed_marker_concatenation() {
    let bracketed = bracketed_marker();
    assert!(bracketed.starts_with(open_marker()));
    assert!(bracketed.ends_with(close_marker()));
    assert!(bracketed.contains(inner_marker()));
    // Legacy contains(open_marker()) check should still work
    assert!(bracketed.contains(open_marker()));
}

#[test]
fn classify_full_reflection() {
    let body = format!("<p>echo: {}</p>", bracketed_marker());
    assert_eq!(classify_probe_reflection(&body), ProbeReflection::Full);
}

#[test]
fn classify_prefix_only_reflection() {
    // server stripped the close segment off the input
    let body = format!("<p>echo: {}{}</p>", open_marker(), inner_marker());
    assert_eq!(
        classify_probe_reflection(&body),
        ProbeReflection::PrefixOnly
    );
}

#[test]
fn classify_suffix_only_reflection() {
    // server stripped the open segment
    let body = format!("<p>echo: {}{}</p>", inner_marker(), close_marker());
    assert_eq!(
        classify_probe_reflection(&body),
        ProbeReflection::SuffixOnly
    );
}

#[test]
fn classify_inner_only_reflection() {
    // server extracted a regex middle, both wraps gone
    let body = format!("<p>echo: {}</p>", inner_marker());
    assert_eq!(classify_probe_reflection(&body), ProbeReflection::InnerOnly);
}

#[test]
fn classify_none_for_unrelated_body() {
    let body = "<p>nothing here</p>".to_string();
    assert_eq!(classify_probe_reflection(&body), ProbeReflection::None);
    // even when individual marker prefix shows up incidentally without
    // the inner anchor, it's still None — single-prefix collisions don't
    // count as reflection.
    let body2 = format!("<p>{} alone</p>", open_marker());
    assert_eq!(classify_probe_reflection(&body2), ProbeReflection::None);
}

#[test]
fn classify_full_wins_over_partial() {
    // Full bracketed AND a stray open_marker elsewhere — should still
    // classify as Full (it's the strongest signal).
    let body = format!("<a>{}</a><p>{}</p>", open_marker(), bracketed_marker());
    assert_eq!(classify_probe_reflection(&body), ProbeReflection::Full);
}

#[test]
fn detected_helper() {
    assert!(ProbeReflection::Full.detected());
    assert!(ProbeReflection::PrefixOnly.detected());
    assert!(ProbeReflection::SuffixOnly.detected());
    assert!(ProbeReflection::InnerOnly.detected());
    assert!(!ProbeReflection::None.detected());
}
