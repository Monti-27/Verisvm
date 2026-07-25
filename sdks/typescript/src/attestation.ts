import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base58, base64, base64nopad, base64url, base64urlnopad } from "@scure/base";

import { envelopeSchema, statementSchema } from "./schema.js";
import {
  type DsseEnvelope,
  type Statement,
  type VerifiedAttestation,
  DSSE_PAYLOAD_TYPE,
} from "./types.js";

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

export function dssePae(payloadType: string, payload: Uint8Array): Uint8Array {
  const header = textEncoder.encode(`DSSEv1 ${textEncoder.encode(payloadType).length} ${payloadType} ${payload.length} `);
  const result = new Uint8Array(header.length + payload.length);
  result.set(header);
  result.set(payload, header.length);
  return result;
}

export function decodeAndVerify(input: unknown): VerifiedAttestation {
  const envelope = envelopeSchema.parse(input) as DsseEnvelope;
  const signature = envelope.signatures[0];
  if (signature === undefined) {
    throw new Error("an attestation must contain exactly one signature");
  }

  const payload = decodeBase64(envelope.payload);
  const statement = statementSchema.parse(JSON.parse(textDecoder.decode(payload))) as Statement;
  validateStatement(statement);

  const publicKey = base58.decode(signature.keyid);
  if (publicKey.length !== 32) {
    throw new Error("invalid operator public key");
  }
  const signatureBytes = decodeBase64(signature.sig);
  if (signatureBytes.length !== 64) {
    throw new Error("invalid signature encoding");
  }
  if (!ed25519.verify(signatureBytes, dssePae(DSSE_PAYLOAD_TYPE, payload), publicKey)) {
    throw new Error("signature verification failed");
  }

  return {
    operator: signature.keyid,
    statement,
    payloadDigest: toHex(sha256(payload)),
  };
}

function validateStatement(statement: Statement): void {
  const deploymentDigest = statement.predicate.job.deployment.executableDigest;
  if (statement.subject[0]?.digest.sha256?.toLowerCase() !== deploymentDigest) {
    throw new Error("statement subject does not describe the job deployment");
  }

  const { executableDigest, outcome } = statement.predicate.evidence;
  const isValid =
    (outcome === "match" && executableDigest === deploymentDigest) ||
    (outcome === "mismatch" && executableDigest !== null && executableDigest !== deploymentDigest) ||
    (outcome === "build_failed" && executableDigest === null);
  if (!isValid) {
    throw new Error("attestation result is inconsistent with the deployed executable");
  }
}

function decodeBase64(value: string): Uint8Array {
  for (const encoding of [base64, base64nopad, base64url, base64urlnopad]) {
    try {
      return encoding.decode(value);
    } catch {
      continue;
    }
  }
  throw new Error("invalid base64 encoding");
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
