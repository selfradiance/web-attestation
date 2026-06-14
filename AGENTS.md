# AGENTS.md — web-attestation

Cryptographic web attestation service. A Cloudflare Worker that fetches a
caller-supplied URL over HTTPS, hashes the response body, and returns an
Ed25519-signed witness statement, gated behind x402 payment.

## Project rules
- MIT licensed, open source.
- Free-tier Cloudflare Workers only. No paid infrastructure, no R2, no SaaS.
- The attestation is a WITNESS-ONLY statement. It asserts that this endpoint
  observed specific bytes at a specific URL at a specific time. It makes NO
  claim that the content is true, legitimate, owned, or trustworthy. Never
  add fields or language implying legitimacy.
- HTTPS targets only. Cap response body size. Do not add VPC bindings.
- The signing key for this service is SEPARATE from the gateway key. Never
  reuse the gateway key here.

## Files That Must Never Be Committed
These mirror .gitignore exactly. Never stage, commit, or push:
- `.env` and `.env.*` files
- Private keys and identity files: `*.pem`, `*.key`, `*-identity.json`, `privvy`
- Project context files: `*PROJECT_CONTEXT.md`, anything under `_context/`

## Commit discipline
- Use explicit `git add <path>`. Never `git add .`.
- Before any push, run `git status` and confirm no ignored file is staged.
