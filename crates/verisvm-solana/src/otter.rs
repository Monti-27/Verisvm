use borsh::BorshDeserialize;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use verisvm_core::SolanaAddress;

use crate::{Error, Result};

pub const OTTER_VERIFY_PROGRAM_ID: &str = "verifycLy8mB96wd9wqq3WDXQwM4oU6r42Th37Db9fC";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtterVerifyRecord {
    pub address: SolanaAddress,
    pub signer: SolanaAddress,
    pub solana_version: String,
    pub repository: String,
    pub commit: String,
    pub arguments: Vec<String>,
    pub deployment_slot: u64,
    pub bump: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedOtterVerifyRecord {
    pub pda_address: SolanaAddress,
    pub record: OtterVerifyRecord,
    pub observed_at_slot: u64,
}

#[derive(BorshDeserialize)]
struct OtterBuildParams {
    address: [u8; 32],
    signer: [u8; 32],
    version: String,
    git_url: String,
    commit: String,
    args: Vec<String>,
    deployment_slot: u64,
    bump: u8,
}

pub fn decode_otter_verify_record(data: &[u8]) -> Result<OtterVerifyRecord> {
    let body = data
        .get(8..)
        .ok_or_else(|| Error::InvalidOtterAccount("account is truncated".to_owned()))?;
    if data[..8] != account_discriminator() {
        return Err(Error::InvalidOtterAccount(
            "account discriminator does not match BuildParams".to_owned(),
        ));
    }
    let params = OtterBuildParams::try_from_slice(body)
        .map_err(|error| Error::InvalidOtterAccount(error.to_string()))?;

    Ok(OtterVerifyRecord {
        address: SolanaAddress::new(params.address),
        signer: SolanaAddress::new(params.signer),
        solana_version: params.version,
        repository: params.git_url,
        commit: params.commit,
        arguments: params.args,
        deployment_slot: params.deployment_slot,
        bump: params.bump,
    })
}

fn account_discriminator() -> [u8; 8] {
    Sha256::digest(b"account:BuildParams")[..8]
        .try_into()
        .expect("SHA-256 prefix has a fixed length")
}

#[cfg(test)]
mod tests {
    use borsh::BorshSerialize;
    use sha2::{Digest as _, Sha256};
    use verisvm_core::SolanaAddress;

    use super::decode_otter_verify_record;

    #[derive(BorshSerialize)]
    struct TestRecord {
        address: [u8; 32],
        signer: [u8; 32],
        version: String,
        git_url: String,
        commit: String,
        args: Vec<String>,
        deployment_slot: u64,
        bump: u8,
    }

    #[test]
    fn decodes_existing_otter_account_layout() {
        let record = TestRecord {
            address: [1; 32],
            signer: [2; 32],
            version: "3.0.0".to_owned(),
            git_url: "https://github.com/example/program".to_owned(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            args: vec!["--library-name".to_owned(), "example".to_owned()],
            deployment_slot: 500,
            bump: 254,
        };
        let mut data = Sha256::digest(b"account:BuildParams")[..8].to_vec();
        data.extend(borsh::to_vec(&record).expect("record should serialize"));

        let decoded = decode_otter_verify_record(&data).expect("record should decode");

        assert_eq!(decoded.address, SolanaAddress::new([1; 32]));
        assert_eq!(decoded.signer, SolanaAddress::new([2; 32]));
        assert_eq!(decoded.deployment_slot, 500);
        assert_eq!(decoded.bump, 254);
    }
}
