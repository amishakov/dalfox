use clap::Args;

use crate::cmd::scan::ScanArgs;

#[derive(Args)]
pub struct FileArgs {
    /// Target file containing URLs to scan
    #[arg(value_name = "FILE")]
    pub file: String,

    #[clap(flatten)]
    pub scan_args: ScanArgs,
}

fn into_scan_args(args: FileArgs) -> ScanArgs {
    let mut scan_args = args.scan_args;
    scan_args.input_type = "file".to_string();
    scan_args.targets = vec![args.file];
    scan_args
}

pub async fn run_file(args: FileArgs) -> crate::cmd::scan::ScanOutcome {
    let scan_args = into_scan_args(args);
    crate::cmd::scan::run_scan(&scan_args).await
}

#[cfg(test)]
mod tests;
