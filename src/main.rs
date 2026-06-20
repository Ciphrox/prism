use std::path::PathBuf;
use clap::{Parser, Subcommand};
use anyhow::Result;

mod server;
mod client;

#[derive(Parser)]
#[command(name = "prism", about = "Multi-path network bonding VPN")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    Pair {
        #[arg(short, long)]
        listen: String,
    },
}

#[derive(Subcommand)]
enum ClientAction {
    Pair {
        #[arg(short, long)]
        server: String,
        #[arg(short, long)]
        pin: String,
    },
}

fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from(".prism"))
        .join("prism")
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config_dir();
    match Cli::parse().command {
        Commands::Server { action: ServerAction::Pair { listen } } =>
            server::pair(&listen, &cfg).await,
        Commands::Client { action: ClientAction::Pair { server, pin } } =>
            client::pair(&server, &pin, &cfg).await,
    }
}
