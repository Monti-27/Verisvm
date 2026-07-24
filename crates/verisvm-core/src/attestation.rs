use std::collections::BTreeMap;

use base64::{
    DecodeError, Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{
    BuildOutcome, BuildPredicate, DSSE_PAYLOAD_TYPE, Digest, DsseEnvelope, DsseSignature, Error,
    PREDICATE_TYPE, ResourceDescriptor, Result, STATEMENT_TYPE, SolanaAddress, Statement,
    VerifiedAttestation,
};

#[must_use]
pub fn build_statement(predicate: BuildPredicate) -> Statement {
    let deployment = &predicate.job.deployment;
    let mut digest = BTreeMap::new();
    digest.insert(
        "sha256".to_owned(),
        deployment.executable_digest.to_string(),
    );

    Statement {
        statement_type: STATEMENT_TYPE.to_owned(),
        subject: vec![ResourceDescriptor {
            name: format!(
                "solana:{}:program:{}",
                deployment.cluster.as_str(),
                deployment.program_id
            ),
            digest,
        }],
        predicate_type: PREDICATE_TYPE.to_owned(),
        predicate,
    }
}

#[must_use]
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let header = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut encoded = Vec::with_capacity(header.len() + payload.len());
    encoded.extend_from_slice(header.as_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

pub fn sign_statement(statement: &Statement, signing_key: &SigningKey) -> Result<DsseEnvelope> {
    validate_statement(statement)?;
    let payload = serde_json::to_vec(statement).map_err(Error::InvalidPayload)?;
    let signature = signing_key.sign(&dsse_pae(DSSE_PAYLOAD_TYPE, &payload));
    let operator = SolanaAddress::new(signing_key.verifying_key().to_bytes());

    Ok(DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_owned(),
        payload: STANDARD.encode(payload),
        signatures: vec![DsseSignature {
            keyid: operator.to_string(),
            sig: STANDARD.encode(signature.to_bytes()),
        }],
    })
}

pub fn decode_and_verify(envelope: &DsseEnvelope) -> Result<VerifiedAttestation> {
    if envelope.payload_type != DSSE_PAYLOAD_TYPE {
        return Err(Error::UnsupportedPayloadType(envelope.payload_type.clone()));
    }
    if envelope.signatures.len() != 1 {
        return Err(Error::InvalidSignatureCount);
    }

    let payload = decode_base64(&envelope.payload).map_err(Error::InvalidPayloadEncoding)?;
    let statement: Statement = serde_json::from_slice(&payload).map_err(Error::InvalidPayload)?;
    validate_statement(&statement)?;

    let signature_entry = &envelope.signatures[0];
    let operator: SolanaAddress = signature_entry
        .keyid
        .parse()
        .map_err(|_| Error::InvalidPublicKey)?;
    let verifying_key =
        VerifyingKey::from_bytes(operator.as_bytes()).map_err(|_| Error::InvalidPublicKey)?;
    let signature_bytes: [u8; 64] = decode_base64(&signature_entry.sig)
        .map_err(|_| Error::InvalidSignatureEncoding)?
        .try_into()
        .map_err(|_| Error::InvalidSignatureEncoding)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&dsse_pae(&envelope.payload_type, &payload), &signature)
        .map_err(|_| Error::SignatureVerificationFailed)?;

    Ok(VerifiedAttestation {
        operator,
        statement,
        payload_digest: hash(&payload),
    })
}

pub fn statement_payload_digest(envelope: &DsseEnvelope) -> Result<Digest> {
    let payload = decode_base64(&envelope.payload).map_err(Error::InvalidPayloadEncoding)?;
    Ok(hash(&payload))
}

fn decode_base64(value: &str) -> std::result::Result<Vec<u8>, DecodeError> {
    STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value))
        .or_else(|_| URL_SAFE.decode(value))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value))
}

fn validate_statement(statement: &Statement) -> Result<()> {
    if statement.statement_type != STATEMENT_TYPE {
        return Err(Error::UnsupportedStatementType(
            statement.statement_type.clone(),
        ));
    }
    if statement.predicate_type != PREDICATE_TYPE {
        return Err(Error::UnsupportedPredicateType(
            statement.predicate_type.clone(),
        ));
    }

    validate_job(&statement.predicate.job)?;
    if statement.predicate.worker.id.trim().is_empty() {
        return Err(Error::InvalidWorker("worker id is empty".to_owned()));
    }
    if statement.predicate.worker.failure_domain.trim().is_empty() {
        return Err(Error::InvalidWorker("failure domain is empty".to_owned()));
    }
    if statement.predicate.observed_at_slot < statement.predicate.job.deployment.deployment_slot {
        return Err(Error::InvalidWorker(
            "observation predates the deployment".to_owned(),
        ));
    }

    let deployment = &statement.predicate.job.deployment;
    if statement.subject.len() != 1
        || statement.subject[0].digest.get("sha256")
            != Some(&deployment.executable_digest.to_string())
    {
        return Err(Error::InvalidSubject);
    }

    let output = statement.predicate.evidence.executable_digest;
    match statement.predicate.evidence.outcome {
        BuildOutcome::Match if output != Some(deployment.executable_digest) => {
            Err(Error::InvalidBuildResult)
        }
        BuildOutcome::Mismatch
            if output.is_none() || output == Some(deployment.executable_digest) =>
        {
            Err(Error::InvalidBuildResult)
        }
        BuildOutcome::BuildFailed if output.is_some() => Err(Error::InvalidBuildResult),
        _ => Ok(()),
    }
}

pub fn validate_job(job: &crate::VerificationJob) -> Result<()> {
    if job.id.trim().is_empty() || job.id.len() > 128 {
        return Err(Error::InvalidJob("job id has an invalid length".to_owned()));
    }
    if !job.source.repository.starts_with("https://")
        || job.source.repository.len() > 2_048
        || job
            .source
            .repository
            .bytes()
            .any(|byte| byte.is_ascii_whitespace())
    {
        return Err(Error::InvalidJob(
            "repository must be a valid HTTPS URL".to_owned(),
        ));
    }
    if !matches!(job.source.commit.len(), 40 | 64)
        || !job
            .source
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::InvalidJob(
            "commit must be a full lowercase hexadecimal object id".to_owned(),
        ));
    }
    if job.recipe.solana_verify_version.trim().is_empty()
        || job.recipe.rust_toolchain.trim().is_empty()
        || job.recipe.solana_toolchain.trim().is_empty()
    {
        return Err(Error::InvalidJob("toolchain version is empty".to_owned()));
    }
    if job.recipe.command.is_empty()
        || job.recipe.command.len() > 64
        || job
            .recipe
            .command
            .iter()
            .any(|argument| argument.is_empty() || argument.len() > 4_096)
    {
        return Err(Error::InvalidJob("build command is invalid".to_owned()));
    }
    Ok(())
}

fn hash(bytes: &[u8]) -> Digest {
    Digest::new(Sha256::digest(bytes).into())
}
