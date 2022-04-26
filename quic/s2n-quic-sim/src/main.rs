// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub use anyhow::Error;
use structopt::StructOpt;

pub type Result<T = (), E = Error> = core::result::Result<T, E>;

mod batch;
mod query;
mod report;
mod run;
mod stats;

#[derive(Debug, StructOpt)]
enum Args {
    Query(query::Query),
    Run(Box<run::Run>),
    Report(report::Report),
    Batch(batch::Batch),
}

fn main() -> Result {
    let format = tracing_subscriber::fmt::format()
        .with_level(false) // don't include levels in formatted output
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_ansi(false)
        .compact(); // Use a less verbose output format.

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .event_format(format)
        .init();

    match Args::from_args() {
        Args::Query(args) => args.run(),
        Args::Run(args) => args.run(),
        Args::Report(args) => args.run(),
        Args::Batch(args) => args.run(),
    }
}
