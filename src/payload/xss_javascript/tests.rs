use super::*;

#[test]
fn test_small_payloads_not_empty() {
    assert!(
        !XSS_JAVASCRIPT_PAYLOADS_SMALL.is_empty(),
        "small payloads list must not be empty"
    );
}

#[test]
fn test_full_payloads_not_empty() {
    assert!(
        !XSS_JAVASCRIPT_PAYLOADS.is_empty(),
        "full payloads list must not be empty"
    );
}

#[test]
fn test_no_empty_payloads() {
    for p in XSS_JAVASCRIPT_PAYLOADS_SMALL {
        assert!(!p.is_empty(), "small payload must not be empty string");
    }
    for p in XSS_JAVASCRIPT_PAYLOADS {
        assert!(!p.is_empty(), "full payload must not be empty string");
    }
}

#[test]
fn test_no_duplicate_small_payloads() {
    let mut seen = std::collections::HashSet::new();
    for p in XSS_JAVASCRIPT_PAYLOADS_SMALL {
        assert!(seen.insert(p), "duplicate small payload: {}", p);
    }
}

#[test]
fn test_no_duplicate_full_payloads() {
    let mut seen = std::collections::HashSet::new();
    for p in XSS_JAVASCRIPT_PAYLOADS {
        assert!(seen.insert(p), "duplicate full payload: {}", p);
    }
}

#[test]
fn test_payloads_contain_execution_primitives() {
    // At least one payload should reference alert, prompt, or confirm
    let has_exec = XSS_JAVASCRIPT_PAYLOADS
        .iter()
        .any(|p| p.contains("alert") || p.contains("prompt") || p.contains("confirm"));
    assert!(has_exec, "payloads should contain execution primitives");
}
