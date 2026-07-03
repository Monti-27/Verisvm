import { base58 } from "@scure/base";
import { z } from "zod";

import { DSSE_PAYLOAD_TYPE, PREDICATE_TYPE, STATEMENT_TYPE } from "./types.js";

const digest = z.string().regex(/^[0-9a-fA-F]{64}$/).transform((value) => value.toLowerCase());
const solanaAddress = z.string().refine((value) => {
  try {
    return base58.decode(value).length === 32;
  } catch {
    return false;
  }
}, "invalid Solana address");
const slot = z.number().int().nonnegative().safe();

export const deploymentSchema = z.object({
  cluster: z.enum(["mainnet_beta", "devnet", "testnet", "localnet"]),
  programId: solanaAddress,
  programDataAddress: solanaAddress.nullable(),
  deploymentSlot: slot,
  executableDigest: digest,
});

export const verificationJobSchema = z.object({
  id: z.string().min(1),
  deployment: deploymentSchema,
  source: z.object({
    repository: z.url().refine((value) => new URL(value).protocol === "https:", "repository must use HTTPS"),
    commit: z.string().regex(/^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/),
    treeDigest: digest,
  }),
  recipe: z.object({
    builderImageDigest: digest,
    solanaVerifyVersion: z.string().min(1),
    rustToolchain: z.string().min(1),
    solanaToolchain: z.string().min(1),
    command: z.array(z.string().min(1)).min(1),
    cargoLockDigest: digest.nullable(),
  }),
});

export const statementSchema = z.object({
  _type: z.literal(STATEMENT_TYPE),
  subject: z.array(
    z.object({
      name: z.string().min(1),
      digest: z.record(z.string(), z.string()),
    }),
  ).length(1),
  predicateType: z.literal(PREDICATE_TYPE),
  predicate: z.object({
    job: verificationJobSchema,
    worker: z.object({
      id: z.string().min(1),
      failureDomain: z.string().min(1),
    }),
    evidence: z.object({
      outcome: z.enum(["match", "mismatch", "build_failed"]),
      executableDigest: digest.nullable(),
      transcriptDigest: digest,
    }),
    observedAtSlot: slot,
  }),
});

export const envelopeSchema = z.object({
  payloadType: z.literal(DSSE_PAYLOAD_TYPE),
  payload: z.string().min(1),
  signatures: z.array(
    z.object({
      keyid: solanaAddress,
      sig: z.string().min(1),
    }),
  ).length(1),
});

export const observedDeploymentSchema = z.object({
  deployment: deploymentSchema,
  observedAtSlot: slot,
});

export const quorumPolicySchema = z
  .object({
    minimumOperators: z.number().int().positive(),
    minimumFailureDomains: z.number().int().positive(),
    maximumAgeSlots: z.number().int().nonnegative().safe().nullable(),
    operatorFailureDomains: z.record(solanaAddress, z.string().min(1)),
  })
  .superRefine((policy, context) => {
    if (policy.minimumFailureDomains > policy.minimumOperators) {
      context.addIssue({
        code: "custom",
        message: "minimum failure domains cannot exceed minimum operators",
      });
    }
    if (Object.keys(policy.operatorFailureDomains).length < policy.minimumOperators) {
      context.addIssue({
        code: "custom",
        message: "operator registry cannot satisfy the minimum operator count",
      });
    }
  });
