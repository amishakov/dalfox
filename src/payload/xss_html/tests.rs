use super::*;

#[test]
fn test_get_dynamic_xss_html_payloads_non_empty() {
    let payloads = get_dynamic_xss_html_payloads();
    assert!(!payloads.is_empty());
}

#[test]
fn test_get_dynamic_xss_html_payloads_contains_markers_and_js() {
    let payloads = get_dynamic_xss_html_payloads();
    let cls = crate::scanning::markers::class_marker().to_lowercase();
    let idm = crate::scanning::markers::id_marker().to_lowercase();
    let has_class = payloads
        .iter()
        .any(|p| p.to_lowercase().contains(&format!("class={}", cls)));
    let has_id = payloads
        .iter()
        .any(|p| p.to_lowercase().contains(&format!("id={}", idm)));
    assert!(has_class || has_id, "should contain class/id marker");
    let has_alert = payloads
        .iter()
        .any(|p| p.to_lowercase().contains("alert(1)"));
    assert!(has_alert, "should include at least one alert(1) variant");
}

#[test]
fn test_attribute_payloads_from_event_module() {
    let attrs = crate::payload::get_dynamic_xss_attribute_payloads();
    assert!(!attrs.is_empty(), "attribute payloads should not be empty");
    assert!(attrs.iter().any(|p| p.starts_with("onerror=")));
    assert!(attrs.iter().any(|p| p.starts_with("onload=")));
    assert!(
        attrs.iter().any(|p| p.contains("alert(1)")),
        "should include alert(1) primitive"
    );
}

#[test]
fn test_get_mxss_payloads_non_empty() {
    let payloads = get_mxss_payloads();
    assert!(!payloads.is_empty(), "mXSS payloads should not be empty");
}

#[test]
fn test_get_mxss_payloads_contains_svg_foreignobject() {
    let payloads = get_mxss_payloads();
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("foreignobject") || p.contains("foreignObject")),
        "should contain SVG foreignObject payloads"
    );
}

#[test]
fn test_get_mxss_payloads_contains_math_mtext() {
    let payloads = get_mxss_payloads();
    assert!(
        payloads.iter().any(|p| p.contains("mtext")),
        "should contain math/mtext payloads"
    );
}

#[test]
fn test_get_mxss_payloads_contains_markers() {
    let payloads = get_mxss_payloads();
    let cls = crate::scanning::markers::class_marker();
    let idm = crate::scanning::markers::id_marker();
    let has_marker = payloads.iter().any(|p| p.contains(cls) || p.contains(idm));
    assert!(has_marker, "mXSS payloads should contain class/id markers");
}

#[test]
fn test_get_protocol_injection_payloads_non_empty() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        !payloads.is_empty(),
        "protocol injection payloads should not be empty"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_javascript_protocol() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.starts_with("javascript:")),
        "should contain javascript: protocol payloads"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_case_variations() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.starts_with("Javascript:")),
        "should contain capitalized javascript: variant"
    );
    assert!(
        payloads.iter().any(|p| p.starts_with("jAvAsCrIpT:")),
        "should contain mixed case javascript: variant"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_tab_bypass() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.contains("java\tscript:")),
        "should contain tab-inserted javascript: variant"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_data_protocol() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.starts_with("data:text/html,")),
        "should contain data: text/html payloads"
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.starts_with("data:text/html;base64,")),
        "should contain data: base64 payloads"
    );
}

#[test]
fn test_get_protocol_injection_payloads_contains_alert() {
    let payloads = get_protocol_injection_payloads();
    assert!(
        payloads.iter().any(|p| p.contains("alert(1)")),
        "should include at least one alert(1) variant"
    );
}

#[test]
fn test_blind_template_placeholder_and_replacement() {
    let tpl = crate::payload::XSS_BLIND_PAYLOADS
        .first()
        .copied()
        .unwrap_or("\"'><script src={}></script>");
    assert!(
        tpl.contains("{}"),
        "blind template should include '{{}}' placeholder"
    );
    let replaced = tpl.replace("{}", "https://callback.example/x");
    assert!(
        replaced.contains("https://callback.example/x"),
        "replaced template should include callback URL"
    );
}
