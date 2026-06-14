# web-attestation

A Cloudflare Worker that fetches a caller-supplied HTTPS URL, hashes the
response body with SHA-256, and returns an Ed25519-signed **witness-only**
byte-observation attestation. Payment is gated with x402.

Current instance: `https://web-attestation.selfradiance.workers.dev`

## What it attests

The signed statement asserts exactly one thing: that this endpoint observed
specific response bytes at a specific URL at a specific time. It makes **no
claim** about the truth, legitimacy, ownership, or trustworthiness of the
content. The signed payload carries `claims: "none"` and a human-readable
notice to that effect.

This is deliberate. A witness statement that asserted legitimacy could be used
to launder a signature into an endorsement. This service signs observations,
not endorsements.

## Endpoints

- `GET /` — free service discovery (JSON).
- `GET /.well-known/web-attestation-key.json` — free Ed25519 verification key (public JWK).
- `GET /attest?url=<https-url>` — x402-gated. Returns the signed attestation on payment.

The target URL must be HTTPS. The response body is hashed up to a 1 MiB cap;
beyond that the attestation reports `truncated: true` and never claims a
complete observation.

## Payment

The `/attest` route returns HTTP 402 with x402 payment requirements (Base
mainnet, USDC, `exact` scheme). A paying client retries with a payment
signature header and receives the signed attestation. The service holds no
custody of buyer funds or keys.

## Signed payload schema

`attestation_type: "byte_observation.v1"`, with `kid`, `attestation_id`,
`observed_at` (ISO 8601 UTC), `canonicalization: "RFC8785-JCS"`, the `request`
(method, url, redirect policy), the `response` (status, ok, content type), the
`body` (hash algorithm, sha256 hex, bytes hashed, completeness, truncation,
max bytes), `claims: "none"`, and a `human_notice`. The output object is
`{ payload, signature, kid }`, where `signature` is base64url Ed25519 over the
RFC 8785 canonical form of `payload`.

## Verifying an attestation

1. Fetch the public key from `/.well-known/web-attestation-key.json`.
2. Canonicalize `payload` with RFC 8785 (JCS).
3. Verify the base64url `signature` over the canonical bytes using the key's `x` value.
4. Confirm `kid` matches the key.

## License

MIT.
