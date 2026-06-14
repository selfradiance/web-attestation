/**
 * Web Attestation Worker — Self-Radiance Web Attestation
 *
 * Required secrets (set via `wrangler secret put`, never committed):
 *   WEB_ATTESTATION_ED25519_PRIVATE_JWK  private Ed25519 JWK for this
 *                                        attestation service only
 *   CDP_API_KEY_ID                       Coinbase Developer Platform key id
 *   CDP_API_KEY_SECRET                   Coinbase Developer Platform key secret
 *
 * Witness-only model:
 *   - GET /                                      free service discovery
 *   - GET /.well-known/web-attestation-key.json  free verification key
 *   - GET /attest?url=<https-url>                x402-gated byte observation
 */

import { Hono } from "hono";
import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import type { RoutesConfig } from "@x402/core/server";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import {
  bazaarResourceServerExtension,
  declareDiscoveryExtension,
} from "@x402/extensions/bazaar";
import { createFacilitatorConfig } from "@coinbase/x402";
import publicKeyJson from "../.well-known/web-attestation-key.json";
import {
  AttestationCoreError,
  HUMAN_NOTICE,
  MAX_BODY_BYTES,
  createByteObservationAttestation,
  importSigningKeyFromEnv,
  validateObservationUrl,
} from "./attestation-core.js";

// ---------------------------------------------------------------------------
// Network configuration. Matches the x402 license gateway's active Base
// mainnet configuration and exact USDC EIP-712 domain values.
// ---------------------------------------------------------------------------
const NETWORK_PRESETS = {
  TESTNET: {
    network: "eip155:84532" as const, // base-sepolia
    usdc: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    eip712: { name: "USDC", version: "2" },
  },
  MAINNET: {
    network: "eip155:8453" as const, // base
    usdc: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    eip712: { name: "USD Coin", version: "2" },
  },
};
const ACTIVE = NETWORK_PRESETS.TESTNET;

// PLACEHOLDER: replace with the service owner's Base address before deploy.
const PAY_TO = "0x155463b78af48b2db07583c266b18e35bee4eed7";
// PLACEHOLDER: 1.00 USDC, matching the smallest price used by the gateway.
const PRICE_ATOMIC_USDC = "1000000";
const PRICE_USDC = "1.00";
const SCHEME = "exact";
const PUBLIC_KEY_PATH = "/.well-known/web-attestation-key.json";

type PublicVerificationKey = Record<string, unknown> & { kid?: unknown };
type JsonSchema = Record<string, unknown>;

const PUBLIC_KEY = publicKeyJson as PublicVerificationKey;
const PUBLIC_KEY_KID =
  typeof PUBLIC_KEY.kid === "string" && PUBLIC_KEY.kid.length > 0
    ? PUBLIC_KEY.kid
    : "web-attestation-key";

const ATTESTATION_OUTPUT_EXAMPLE = {
  payload: {
    attestation_type: "byte_observation.v1",
    kid: PUBLIC_KEY_KID,
    attestation_id: "WA-example",
    observed_at: "2026-06-14T00:00:00.000Z",
    canonicalization: "RFC8785-JCS",
    request: {
      method: "GET",
      url: "https://example.com/",
      redirect_policy: "manual_no_follow",
    },
    response: {
      http_status: 200,
      ok: true,
      content_type: "text/html",
    },
    body: {
      hash_alg: "sha-256",
      sha256_hex:
        "0000000000000000000000000000000000000000000000000000000000000000",
      hash_subject: "response_body_bytes",
      bytes_hashed: 1256,
      complete_body_observed: true,
      truncated: false,
      max_bytes: MAX_BODY_BYTES,
    },
    claims: "none",
    human_notice: HUMAN_NOTICE,
  },
  signature: "base64url-ed25519-signature-over-canonical-payload",
  kid: PUBLIC_KEY_KID,
};

const ATTESTATION_OUTPUT_SCHEMA = {
  type: "object",
  properties: {
    payload: {
      type: "object",
      properties: {
        attestation_type: { type: "string", const: "byte_observation.v1" },
        kid: { type: "string" },
        attestation_id: { type: "string" },
        observed_at: { type: "string" },
        canonicalization: { type: "string", const: "RFC8785-JCS" },
        request: {
          type: "object",
          properties: {
            method: { type: "string", const: "GET" },
            url: { type: "string" },
            redirect_policy: {
              type: "string",
              const: "manual_no_follow",
            },
          },
          required: ["method", "url", "redirect_policy"],
          additionalProperties: false,
        },
        response: {
          type: "object",
          properties: {
            http_status: { type: "number" },
            ok: { type: "boolean" },
            content_type: { type: "string" },
          },
          required: ["http_status", "ok", "content_type"],
          additionalProperties: false,
        },
        body: {
          type: "object",
          properties: {
            hash_alg: { type: "string", const: "sha-256" },
            sha256_hex: { type: "string", pattern: "^[0-9a-f]{64}$" },
            hash_subject: {
              type: "string",
              const: "response_body_bytes",
            },
            bytes_hashed: { type: "number" },
            complete_body_observed: { type: "boolean" },
            truncated: { type: "boolean" },
            max_bytes: { type: "number", const: MAX_BODY_BYTES },
          },
          required: [
            "hash_alg",
            "sha256_hex",
            "hash_subject",
            "bytes_hashed",
            "complete_body_observed",
            "truncated",
            "max_bytes",
          ],
          additionalProperties: false,
        },
        claims: { type: "string", const: "none" },
        human_notice: { type: "string", const: HUMAN_NOTICE },
      },
      required: [
        "attestation_type",
        "kid",
        "attestation_id",
        "observed_at",
        "canonicalization",
        "request",
        "response",
        "body",
        "claims",
        "human_notice",
      ],
      additionalProperties: false,
    },
    signature: { type: "string" },
    kid: { type: "string" },
  },
  required: ["payload", "signature", "kid"],
  additionalProperties: false,
} satisfies JsonSchema;

const routes: RoutesConfig = {
  "/attest": {
    accepts: {
      scheme: SCHEME,
      payTo: PAY_TO,
      network: ACTIVE.network,
      price: {
        asset: ACTIVE.usdc,
        amount: PRICE_ATOMIC_USDC,
        extra: ACTIVE.eip712,
      },
    },
    description:
      "Returns an Ed25519-signed witness-only byte-observation attestation for a caller-supplied HTTPS URL.",
    mimeType: "application/json",
    serviceName: "Self-Radiance Web Attestation",
    extensions: declareDiscoveryExtension({
      output: {
        example: ATTESTATION_OUTPUT_EXAMPLE,
        schema: ATTESTATION_OUTPUT_SCHEMA,
      },
    }),
  },
};

function publicKeyUrl(requestUrl: string): string {
  return new URL(PUBLIC_KEY_PATH, requestUrl).toString();
}

function coreErrorStatus(error: AttestationCoreError): 400 | 500 | 502 {
  if (error.code.startsWith("ERR_URL")) return 400;
  if (error.code === "ERR_SIGNING_KEY_MISSING") return 500;
  return 502;
}

function errorPayload(error: unknown): { error: string; code?: string } {
  if (error instanceof AttestationCoreError) {
    return { error: error.message, code: error.code };
  }
  if (error instanceof Error) {
    return { error: error.message };
  }
  return { error: "Unknown attestation error." };
}

// App is built lazily on first request so CDP credentials can be passed
// explicitly from the Worker env binding, matching the x402 license gateway.
function buildApp(env: Env): Hono<{ Bindings: Env }> {
  const facilitator = new HTTPFacilitatorClient(
    createFacilitatorConfig(env.CDP_API_KEY_ID, env.CDP_API_KEY_SECRET),
  );

  const app = new Hono<{ Bindings: Env }>();
  const server = new x402ResourceServer(facilitator)
    .register(ACTIVE.network, new ExactEvmScheme())
    .registerExtension(bazaarResourceServerExtension);

  app.use(paymentMiddleware(routes, server));

  app.get("/", (c) => {
    return c.json({
      name: "Self-Radiance Web Attestation",
      model: "witness-only",
      notice: HUMAN_NOTICE,
      payment: {
        rail: "x402",
        x402Version: 2,
        scheme: SCHEME,
        network: ACTIVE.network,
        currency: "USDC",
        amount_atomic_usdc: PRICE_ATOMIC_USDC,
        price_usdc: PRICE_USDC,
        payTo: PAY_TO,
        attestUrl: "/attest?url=<https-url>",
      },
      public_key: {
        url: publicKeyUrl(c.req.url),
        kid: PUBLIC_KEY_KID,
      },
    });
  });

  app.get(PUBLIC_KEY_PATH, (c) => {
    return c.json(PUBLIC_KEY, 200, { "content-type": "application/json" });
  });

  app.get("/attest", async (c) => {
    try {
      const signingKey = await importSigningKeyFromEnv(c.env);
      const url = validateObservationUrl(c.req.query("url"));
      const attestation = await createByteObservationAttestation({
        url,
        signingKey,
        kid: PUBLIC_KEY_KID,
      });

      return c.json(attestation);
    } catch (error) {
      if (error instanceof AttestationCoreError) {
        return c.json(errorPayload(error), coreErrorStatus(error));
      }

      return c.json(errorPayload(error), 502);
    }
  });

  return app;
}

let cachedApp: Hono<{ Bindings: Env }> | undefined;

export default {
  fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Response | Promise<Response> {
    if (!cachedApp) cachedApp = buildApp(env);
    return cachedApp.fetch(request, env, ctx);
  },
};
