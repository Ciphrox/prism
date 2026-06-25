use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod client;
mod server;

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
        #[arg(long)]
        name: Option<String>,
    },
    Start {
        #[arg(long, default_value = "53999")]
        port: u16,
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
    Connect {
        #[arg(long)]
        name: String,
        #[arg(short, long)]
        server: String,
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
        Commands::Server {
            action: ServerAction::Pair { listen, name },
        } => server::pair(&listen, &cfg, name).await,
        Commands::Server {
            action: ServerAction::Start { port },
        } => server::start(&cfg, port).await,

        Commands::Client {
            action: ClientAction::Pair { server, pin },
        } => client::pair(&server, &pin, &cfg).await,
        Commands::Client {
            action: ClientAction::Connect { name, server },
        } => client::connect(&cfg, &name, &server).await,
    }
}
