use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Url;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use verisvm_core::{Cluster, Deployment, ObservedDeployment, SolanaAddress};

use crate::{
    Error, OTTER_VERIFY_PROGRAM_ID, ObservedOtterVerifyRecord, Result, decode_otter_verify_record,
    decode_program_data, decode_program_pointer,
};

const UPGRADEABLE_LOADER_ID: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

pub struct SolanaRpc {
    client: reqwest::Client,
    url: Url,
    request_id: AtomicU64,
}

impl SolanaRpc {
    pub fn new(url: &str) -> Result<Self> {
        let url = Url::parse(url).map_err(|error| Error::InvalidRpcUrl(error.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(Error::InvalidRpcUrl(
                "RPC URL must use HTTP or HTTPS".to_owned(),
            ));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("verisvm/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            client,
            url,
            request_id: AtomicU64::new(1),
        })
    }

    pub async fn fetch_deployment(
        &self,
        cluster: Cluster,
        program_id: SolanaAddress,
    ) -> Result<ObservedDeployment> {
        let program = self.get_account(&program_id.to_string()).await?;
        if program.value.owner != UPGRADEABLE_LOADER_ID {
            return Err(Error::UnsupportedOwner(program.value.owner));
        }
        if !program.value.executable {
            return Err(Error::ProgramNotExecutable);
        }

        let program_data_address = decode_program_pointer(&program.value.decode_data()?)?;
        let program_data = self.get_account(&program_data_address.to_string()).await?;
        if program_data.value.owner != UPGRADEABLE_LOADER_ID {
            return Err(Error::UnsupportedOwner(program_data.value.owner));
        }
        let (deployment_slot, _, executable_digest) =
            decode_program_data(&program_data.value.decode_data()?)?;

        Ok(ObservedDeployment {
            deployment: Deployment {
                cluster,
                program_id,
                program_data_address: Some(program_data_address),
                deployment_slot,
                executable_digest,
            },
            observed_at_slot: program_data.context.slot,
        })
    }

    pub async fn fetch_otter_records(
        &self,
        program_id: SolanaAddress,
    ) -> Result<Vec<ObservedOtterVerifyRecord>> {
        let params = serde_json::json!([
            OTTER_VERIFY_PROGRAM_ID,
            {
                "commitment": "finalized",
                "encoding": "base64",
                "filters": [{"memcmp": {"offset": 8, "bytes": program_id.to_string()}}],
                "withContext": true
            }
        ]);
        let response: RpcContextValue<Vec<RpcProgramAccount>> =
            self.request("getProgramAccounts", params).await?;
        let observed_at_slot = response.context.slot;
        response
            .value
            .into_iter()
            .map(|record| {
                let decoded = decode_otter_verify_record(&record.account.decode_data()?)?;
                if decoded.address != program_id {
                    return Err(Error::InvalidOtterAccount(
                        "record address does not match requested program".to_owned(),
                    ));
                }
                let pda_address = record
                    .pubkey
                    .parse()
                    .map_err(|_| Error::InvalidOtterAccount("invalid PDA address".to_owned()))?;
                Ok(ObservedOtterVerifyRecord {
                    pda_address,
                    record: decoded,
                    observed_at_slot,
                })
            })
            .collect()
    }

    async fn get_account(&self, address: &str) -> Result<RpcContextValue<RpcAccount>> {
        let params = serde_json::json!([
            address,
            {"commitment": "finalized", "encoding": "base64"}
        ]);
        let response: RpcContextValue<Option<RpcAccount>> =
            self.request("getAccountInfo", params).await?;
        let value = response
            .value
            .ok_or_else(|| Error::AccountNotFound(address.to_owned()))?;
        Ok(RpcContextValue {
            context: response.context,
            value,
        })
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let request = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let response = self
            .client
            .post(self.url.clone())
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json::<RpcResponse<T>>()
            .await?;
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (_, Some(error)) => Err(Error::Rpc {
                code: error.code,
                message: error.message,
            }),
            _ => Err(Error::Rpc {
                code: -1,
                message: "response contained neither result nor error".to_owned(),
            }),
        }
    }
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct RpcContextValue<T> {
    context: RpcContext,
    value: T,
}

#[derive(Deserialize)]
struct RpcContext {
    slot: u64,
}

#[derive(Deserialize)]
struct RpcProgramAccount {
    pubkey: String,
    account: RpcAccount,
}

#[derive(Deserialize)]
struct RpcAccount {
    data: (String, String),
    executable: bool,
    owner: String,
}

impl RpcAccount {
    fn decode_data(&self) -> Result<Vec<u8>> {
        if self.data.1 != "base64" {
            return Err(Error::InvalidAccountEncoding);
        }
        STANDARD
            .decode(&self.data.0)
            .map_err(|_| Error::InvalidAccountEncoding)
    }
}
