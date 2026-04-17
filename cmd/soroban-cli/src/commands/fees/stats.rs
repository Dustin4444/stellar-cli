use soroban_rpc::FeeStat;

use crate::{commands::global, config::network, rpc};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Network(#[from] network::Error),
    #[error(transparent)]
    Rpc(#[from] rpc::Error),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, clap::ValueEnum, Default)]
pub enum OutputFormat {
    /// Text output of network info
    #[default]
    Text,
    /// JSON result of the RPC request
    Json,
    /// Formatted (multiline) JSON output of the RPC request
    JsonFormatted,
}

#[derive(Debug, clap::Parser)]
pub struct Cmd {
    #[command(flatten)]
    pub network: network::Args,

    /// Format of the output
    #[arg(long, value_enum, default_value_t)]
    pub output: OutputFormat,
}

impl Cmd {
    pub async fn run(&self, global_args: &global::Args) -> Result<(), Error> {
        let network = self.network.get(&global_args.locator)?;
        let client = network.rpc_client()?;
        let fee_stats = client.get_fee_stats().await?;

        match self.output {
            OutputFormat::Text => {
                println!("Soroban Inclusion Fee:");
                print_fee_stat(&fee_stats.soroban_inclusion_fee);
                println!();
                println!("Inclusion Fee:");
                print_fee_stat(&fee_stats.inclusion_fee);
                println!();
                println!("Latest Ledger: {}", fee_stats.latest_ledger);
            }
            OutputFormat::Json => println!("{}", serde_json::to_string(&fee_stats)?),
            OutputFormat::JsonFormatted => {
                println!("{}", serde_json::to_string_pretty(&fee_stats)?);
            }
        }

        Ok(())
    }
}

fn print_fee_stat(stat: &FeeStat) {
    println!("  Max:               {}", stat.max);
    println!("  Min:               {}", stat.min);
    println!("  Mode:              {}", stat.mode);
    println!("  P10:               {}", stat.p10);
    println!("  P20:               {}", stat.p20);
    println!("  P30:               {}", stat.p30);
    println!("  P40:               {}", stat.p40);
    println!("  P50:               {}", stat.p50);
    println!("  P60:               {}", stat.p60);
    println!("  P70:               {}", stat.p70);
    println!("  P80:               {}", stat.p80);
    println!("  P90:               {}", stat.p90);
    println!("  P95:               {}", stat.p95);
    println!("  P99:               {}", stat.p99);
    println!("  Transaction Count: {}", stat.transaction_count);
    println!("  Ledger Count:      {}", stat.ledger_count);
}
