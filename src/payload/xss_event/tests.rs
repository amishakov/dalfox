use super::*;

#[test]
fn test_attribute_payloads_non_empty() {
    let payloads = get_dynamic_xss_attribute_payloads();
    assert!(
        !payloads.is_empty(),
        "attribute payloads should not be empty"
    );
}

#[test]
fn test_attribute_payloads_contains_event_names() {
    let payloads = get_dynamic_xss_attribute_payloads();
    assert!(
        payloads.iter().any(|p| p.starts_with("onerror=")),
        "should contain onerror= variants"
    );
    assert!(
        payloads.iter().any(|p| p.starts_with("onload=")),
        "should contain onload= variants"
    );
    assert!(
        payloads.iter().any(|p| p.starts_with("onmouseover=")),
        "should contain onmouseover= variants"
    );
    assert!(
        payloads.iter().any(|p| p.starts_with("onclick=")),
        "should contain onclick= variants"
    );
}

#[test]
fn test_js_payloads_exposed_and_contains_alert() {
    let js = crate::payload::XSS_JAVASCRIPT_PAYLOADS_SMALL;
    assert!(!js.is_empty(), "JS payload list should not be empty");
    assert!(
        js.iter().any(|p| p.contains("alert(1)")),
        "should include at least one alert(1) primitive"
    );
}
