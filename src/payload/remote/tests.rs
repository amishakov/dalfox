use super::*;

#[test]
fn test_sanitize_lines_strips_comments_and_blanks() {
    let input = "payload1\n  \n# comment\n// comment\n; comment\n  payload2  \n";
    let result = sanitize_lines(input);
    assert_eq!(result, vec!["payload1", "payload2"]);
}

#[test]
fn test_sanitize_lines_trims_whitespace() {
    let input = "  <script>alert(1)</script>  \n\t<img src=x>\t";
    let result = sanitize_lines(input);
    assert_eq!(result, vec!["<script>alert(1)</script>", "<img src=x>"]);
}

#[test]
fn test_sanitize_lines_empty_input() {
    assert!(sanitize_lines("").is_empty());
    assert!(sanitize_lines("   \n  \n").is_empty());
    assert!(sanitize_lines("# only comments\n// more\n").is_empty());
}

#[test]
fn test_dedup_and_sort_removes_duplicates() {
    let input = vec![
        "b".to_string(),
        "a".to_string(),
        "b".to_string(),
        "c".to_string(),
        "a".to_string(),
    ];
    let result = dedup_and_sort(input);
    assert_eq!(result, vec!["a", "b", "c"]);
}

#[test]
fn test_dedup_and_sort_preserves_case() {
    let input = vec!["Alert".to_string(), "alert".to_string()];
    let result = dedup_and_sort(input);
    assert_eq!(result.len(), 2, "case-sensitive dedup");
}

#[test]
fn test_dedup_and_sort_empty() {
    assert!(dedup_and_sort(vec![]).is_empty());
}

#[test]
fn test_ensure_default_registries_seeds_providers() {
    ensure_default_registries();
    let providers = list_payload_providers();
    assert!(providers.contains(&"payloadbox".to_string()));
    assert!(providers.contains(&"portswigger".to_string()));
}

#[test]
fn test_ensure_default_registries_seeds_wordlists() {
    ensure_default_registries();
    let providers = list_wordlist_providers();
    assert!(providers.contains(&"assetnote".to_string()));
    assert!(providers.contains(&"burp".to_string()));
}

#[test]
fn test_register_custom_payload_provider() {
    register_payload_provider(
        "custom",
        vec!["https://example.com/payloads.txt".to_string()],
    );
    let providers = list_payload_providers();
    assert!(providers.contains(&"custom".to_string()));
}

#[test]
fn test_register_payload_provider_case_insensitive() {
    register_payload_provider("MyProvider", vec!["https://example.com/p.txt".to_string()]);
    let providers = list_payload_providers();
    assert!(providers.contains(&"myprovider".to_string()));
}

#[test]
fn test_collect_payload_urls_unknown_provider_returns_empty() {
    let urls = collect_payload_provider_urls(&["nonexistent".to_string()]);
    assert!(urls.is_empty());
}

#[test]
fn test_collect_payload_urls_known_provider() {
    ensure_default_registries();
    let urls = collect_payload_provider_urls(&["payloadbox".to_string()]);
    assert!(!urls.is_empty());
    assert!(urls[0].contains("payloadbox"));
}

#[test]
fn test_has_remote_payloads_initially_depends_on_test_order() {
    // This just checks that the function doesn't panic
    let _ = has_remote_payloads();
}

#[test]
fn test_has_remote_wordlists_does_not_panic() {
    let _ = has_remote_wordlists();
}
