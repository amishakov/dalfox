use super::*;
use clap::Parser;

#[derive(Parser)]
struct TestCli {
    #[command(flatten)]
    args: PipeArgs,
}

#[test]
fn test_into_scan_args_sets_pipe_mode_and_clears_targets() {
    let cli = TestCli::parse_from(["dalfox-test"]);
    let scan_args = into_scan_args(cli.args);
    assert_eq!(scan_args.input_type, "pipe");
    assert!(scan_args.targets.is_empty());
}
