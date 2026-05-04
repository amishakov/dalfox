use super::*;
use clap::Parser;

#[derive(Parser)]
struct TestCli {
    #[command(flatten)]
    args: UrlArgs,
}

#[test]
fn test_into_scan_args_sets_url_mode_and_target() {
    let cli = TestCli::parse_from(["dalfox-test", "--url", "https://example.com"]);
    let scan_args = into_scan_args(cli.args);
    assert_eq!(scan_args.input_type, "url");
    assert_eq!(scan_args.targets, vec!["https://example.com".to_string()]);
}

#[tokio::test]
async fn test_run_url_executes_scan_path_without_panic() {
    let cli = TestCli::parse_from([
        "dalfox-test",
        "--url",
        "http://[::1",
        "--format",
        "json",
        "-S",
    ]);
    run_url(cli.args).await;
}
