use super::{PayloadArgs, fetch_and_print_remote, print_summary, run_payload, uri_scheme_payloads};

#[test]
fn test_uri_scheme_payloads_shape() {
    let payloads = uri_scheme_payloads();
    assert_eq!(payloads.len(), 5);
    assert!(payloads.iter().any(|p| p.starts_with("javascript:")));
    assert!(payloads.iter().all(|p| !p.is_empty()));
}

#[test]
fn test_run_payload_known_selectors_do_not_panic() {
    run_payload(PayloadArgs {
        selector: Some("event-handlers".to_string()),
    });
    run_payload(PayloadArgs {
        selector: Some("useful-tags".to_string()),
    });
    run_payload(PayloadArgs {
        selector: Some("uri-scheme".to_string()),
    });
}

#[test]
fn test_run_payload_unknown_and_none_do_not_panic() {
    run_payload(PayloadArgs {
        selector: Some("not-a-selector".to_string()),
    });
    run_payload(PayloadArgs { selector: None });
}

#[test]
fn test_run_payload_debug_paths_do_not_panic() {
    let prev = crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed);
    crate::DEBUG.store(true, std::sync::atomic::Ordering::Relaxed);

    run_payload(PayloadArgs {
        selector: Some("event-handlers".to_string()),
    });
    run_payload(PayloadArgs {
        selector: Some("useful-tags".to_string()),
    });
    run_payload(PayloadArgs {
        selector: Some("uri-scheme".to_string()),
    });

    crate::DEBUG.store(prev, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn test_run_payload_remote_selectors_dispatch_without_network_after_unknown_init() {
    // Prime remote cache to empty so provider selectors avoid network fetch in tests.
    fetch_and_print_remote("__unknown_provider__");
    run_payload(PayloadArgs {
        selector: Some("payloadbox".to_string()),
    });
    run_payload(PayloadArgs {
        selector: Some("portswigger".to_string()),
    });
}

#[test]
fn test_fetch_and_print_remote_unknown_provider_no_network_path() {
    fetch_and_print_remote("__unknown_provider__");
}

#[test]
fn test_print_summary_executes() {
    print_summary();
}
