use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, de::DeserializeOwned};
use verisvm_core::{
    Cluster, DsseEnvelope, ObservedDeployment, QuorumPolicy, SolanaAddress, VerificationJob,
    decode_and_verify, evaluate,
};
use verisvm_solana::SolanaRpc;

#[derive(Debug, Parser)]
#[command(
    name = "verisvm",
    version,
    about = "Evaluate Solana program integrity evidence"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Inspect {
        #[arg(long)]
        attestation: PathBuf,
    },
    Evaluate {
        #[arg(long)]
        job: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, required = true)]
        attestation: Vec<PathBuf>,
    },
    EvaluateBundle {
        #[arg(long)]
        bundle: PathBuf,
    },
    Snapshot {
        #[arg(long)]
        program_id: SolanaAddress,
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc_url: String,
        #[arg(long, value_enum, default_value_t = CliCluster::MainnetBeta)]
        cluster: CliCluster,
    },
    OtterRecords {
        #[arg(long)]
        program_id: SolanaAddress,
        #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
        rpc_url: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliCluster {
    MainnetBeta,
    Devnet,
    Testnet,
    Localnet,
}

impl From<CliCluster> for Cluster {
    fn from(value: CliCluster) -> Self {
        match value {
            CliCluster::MainnetBeta => Self::MainnetBeta,
            CliCluster::Devnet => Self::Devnet,
            CliCluster::Testnet => Self::Testnet,
            CliCluster::Localnet => Self::Localnet,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvaluationBundle {
    job: VerificationJob,
    deployment: ObservedDeployment,
    policy: QuorumPolicy,
    attestations: Vec<DsseEnvelope>,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Inspect { attestation } => {
            let envelope = read_json(&attestation)?;
            let verified = decode_and_verify(&envelope)
                .with_context(|| format!("failed to verify {}", attestation.display()))?;
            println!("{}", serde_json::to_string_pretty(&verified)?);
        }
        Command::Evaluate {
            job,
            deployment,
            policy,
            attestation,
        } => {
            let job = read_json::<VerificationJob>(&job)?;
            let deployment = read_json::<ObservedDeployment>(&deployment)?;
            let policy = read_json::<QuorumPolicy>(&policy)?;
            let attestations = attestation
                .iter()
                .map(read_json::<DsseEnvelope>)
                .collect::<Result<Vec<_>>>()?;
            let decision = evaluate(&job, &deployment, &policy, &attestations)?;
            println!("{}", serde_json::to_string_pretty(&decision)?);
        }
        Command::EvaluateBundle { bundle } => {
            let bundle = read_json::<EvaluationBundle>(&bundle)?;
            let decision = evaluate(
                &bundle.job,
                &bundle.deployment,
                &bundle.policy,
                &bundle.attestations,
            )?;
            println!("{}", serde_json::to_string_pretty(&decision)?);
        }
        Command::Snapshot {
            program_id,
            rpc_url,
            cluster,
        } => {
            let rpc = SolanaRpc::new(&rpc_url)?;
            let deployment = rpc.fetch_deployment(cluster.into(), program_id).await?;
            println!("{}", serde_json::to_string_pretty(&deployment)?);
        }
        Command::OtterRecords {
            program_id,
            rpc_url,
        } => {
            let rpc = SolanaRpc::new(&rpc_url)?;
            let records = rpc.fetch_otter_records(program_id).await?;
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}
