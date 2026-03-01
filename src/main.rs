//! lancer-sqlmap
//! Rust clone of sqlmap. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-sqlmap", version, about = "Rust clone of sqlmap")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-sqlmap - scaffold ready. Implement per plan.md.");
    Ok(())
}
