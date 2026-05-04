use super::{init_remote_resources, init_remote_resources_with_options};

#[tokio::test]
async fn test_init_remote_resources_noop_when_no_providers() {
    let payloads: Vec<String> = vec![];
    let wordlists: Vec<String> = vec![];
    let result = init_remote_resources(&payloads, &wordlists).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_init_remote_resources_with_options_accepts_unknown_provider_tokens() {
    let payloads = vec!["__unknown_payload_provider__".to_string()];
    let wordlists = vec!["__unknown_wordlist_provider__".to_string()];
    let result = init_remote_resources_with_options(&payloads, &wordlists, Some(1), None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_init_remote_resources_accepts_unknown_provider_tokens() {
    let payloads = vec!["__unknown_payload_provider__".to_string()];
    let wordlists = vec!["__unknown_wordlist_provider__".to_string()];
    let result = init_remote_resources(&payloads, &wordlists).await;
    assert!(result.is_ok());
}
