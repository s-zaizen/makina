mod api;
mod feedback;
mod infra;
mod logging;

use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
#[command(name = "makina", about = "ML-enhanced security scanner", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the API server (serves frontend at localhost:7373)
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 7373)]
        port: u16,
    },
    /// Retrain the ML model from accumulated feedback labels
    Retrain {
        /// Push training job to RunPod (opt-in)
        #[arg(long)]
        runpod: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve { host, port } => {
            feedback::store::init_db()?;
            info!("makina server starting on http://{}:{}", host, port);
            info!("Frontend: run `npm run dev` in frontend/");
            api::serve(&host, port).await?;
        }
        Commands::Retrain { runpod } => {
            let stats = feedback::store::get_stats()?;
            println!(
                "Labels: {} (TP: {}, FP: {})",
                stats.total_labels, stats.tp_count, stats.fp_count
            );
            println!("Model stage: {}", stats.model_stage);
            if stats.total_labels < 200 {
                println!(
                    "Need {} more labels before retraining.",
                    200 - stats.total_labels
                );
                return Ok(());
            }
            if runpod {
                println!("RunPod integration: coming in Stage 3 (requires MCP connection).");
            } else {
                println!("CPU retraining: invoke `python -m makina_ml.train` in ml/ directory.");
            }
        }
    }

    Ok(())
}
