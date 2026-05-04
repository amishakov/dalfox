use super::*;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

#[test]
fn test_detect_angular_from_body() {
    let headers = make_headers(&[]);
    let body = "<html><div ng-app ng-controller='MainCtrl'>{{name}}</div></html>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Angular));
}

#[test]
fn test_detect_react_from_body() {
    let headers = make_headers(&[]);
    let body = "<div id='root' data-reactroot></div>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::React));
}

#[test]
fn test_detect_vue_from_body() {
    let headers = make_headers(&[]);
    let body = "<div data-v-abc123 class='container'></div>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Vue));
}

#[test]
fn test_detect_jquery_from_body() {
    let headers = make_headers(&[]);
    let body = "<script src='https://code.jquery.com/jquery.min.js'></script>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::JQuery));
}

#[test]
fn test_detect_wordpress_from_header() {
    let headers = make_headers(&[("x-generator", "WordPress 6.0")]);
    let result = detect_technologies(&headers, None);
    assert!(result.has(&TechType::WordPress));
}

#[test]
fn test_detect_express_from_header() {
    let headers = make_headers(&[("x-powered-by", "Express")]);
    let result = detect_technologies(&headers, None);
    assert!(result.has(&TechType::Express));
}

#[test]
fn test_detect_php_from_header() {
    let headers = make_headers(&[("x-powered-by", "PHP/8.1")]);
    let result = detect_technologies(&headers, None);
    assert!(result.has(&TechType::PHP));
}

#[test]
fn test_no_tech_detected() {
    let headers = make_headers(&[("server", "nginx")]);
    let result = detect_technologies(&headers, Some("<html><body>ok</body></html>"));
    assert!(result.is_empty());
}

#[test]
fn test_multiple_techs_detected() {
    let headers = make_headers(&[]);
    let body = "<div ng-app></div><script src='jquery.min.js'></script>";
    let result = detect_technologies(&headers, Some(body));
    assert!(result.has(&TechType::Angular));
    assert!(result.has(&TechType::JQuery));
}

#[test]
fn test_angular_payloads_generated() {
    let mut result = TechDetectionResult::default();
    result.detected.push(TechDetection {
        tech: TechType::Angular,
        evidence: "test".to_string(),
    });
    let payloads = get_tech_specific_payloads(&result);
    assert!(!payloads.is_empty());
    assert!(payloads.iter().any(|p| p.contains("constructor")));
}

#[test]
fn test_jquery_payloads_generated() {
    let mut result = TechDetectionResult::default();
    result.detected.push(TechDetection {
        tech: TechType::JQuery,
        evidence: "test".to_string(),
    });
    let payloads = get_tech_specific_payloads(&result);
    assert!(payloads.iter().any(|p| p.contains("globalEval")));
}

#[test]
fn test_display_tech_types() {
    assert_eq!(format!("{}", TechType::Angular), "Angular");
    assert_eq!(format!("{}", TechType::JQuery), "jQuery");
    assert_eq!(format!("{}", TechType::WordPress), "WordPress");
}
