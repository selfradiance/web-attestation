import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_BODY_BYTES,
  canonicalPayloadBytes,
  canonicalizeJcs,
  createByteObservationAttestation,
} from "../src/attestation-core.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

test("creates a byte-observation attestation and verifies its Ed25519 signature", async () => {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const fixtureBody = encoder.encode("small fixture response");
  let observedFetch;

  const attestation = await createByteObservationAttestation({
    url: "https://example.test/resource?x=1",
    signingKey: privateKey,
    kid: "test-key-1",
    now: () => new Date("2026-06-14T12:00:00.000Z"),
    idGenerator: () => "WA-testfixture",
    fetcher: async (url, init) => {
      observedFetch = { url, init };
      return new Response(fixtureBody, {
        status: 201,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
        },
      });
    },
  });

  assert.deepEqual(Object.keys(attestation.payload), [
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
  ]);
  assert.equal(attestation.kid, "test-key-1");
  assert.equal(attestation.payload.kid, "test-key-1");
  assert.equal(attestation.payload.attestation_type, "byte_observation.v1");
  assert.equal(attestation.payload.attestation_id, "WA-testfixture");
  assert.equal(attestation.payload.observed_at, "2026-06-14T12:00:00.000Z");
  assert.equal(attestation.payload.canonicalization, "RFC8785-JCS");
  assert.deepEqual(attestation.payload.request, {
    method: "GET",
    url: "https://example.test/resource?x=1",
    redirect_policy: "manual_no_follow",
  });
  assert.deepEqual(attestation.payload.response, {
    http_status: 201,
    ok: true,
    content_type: "text/plain; charset=utf-8",
  });
  assert.equal(attestation.payload.body.hash_alg, "sha-256");
  assert.equal(attestation.payload.body.hash_subject, "response_body_bytes");
  assert.equal(attestation.payload.body.bytes_hashed, fixtureBody.byteLength);
  assert.equal(attestation.payload.body.complete_body_observed, true);
  assert.equal(attestation.payload.body.truncated, false);
  assert.equal(attestation.payload.body.max_bytes, MAX_BODY_BYTES);
  assert.equal(attestation.payload.claims, "none");
  assert.match(
    attestation.payload.human_notice,
    /No claim as to truth, legitimacy, ownership, or trustworthiness/,
  );
  assert.deepEqual(observedFetch, {
    url: "https://example.test/resource?x=1",
    init: {
      method: "GET",
      redirect: "manual",
      headers: {
        "Accept-Encoding": "identity",
      },
    },
  });

  const digest = await crypto.subtle.digest("SHA-256", fixtureBody);
  assert.equal(attestation.payload.body.sha256_hex, toHex(new Uint8Array(digest)));

  const isValid = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    base64UrlToBytes(attestation.signature),
    canonicalPayloadBytes(attestation.payload),
  );
  assert.equal(isValid, true);
});

test("canonicalization produces deterministic signed bytes", () => {
  const left = {
    z: 3,
    a: {
      d: "later",
      c: ["same", true, null],
    },
  };
  const right = {
    a: {
      c: ["same", true, null],
      d: "later",
    },
    z: 3,
  };
  const expected = '{"a":{"c":["same",true,null],"d":"later"},"z":3}';
  const leftCanonical = canonicalizeJcs(left);
  const rightCanonical = canonicalizeJcs(right);

  assert.equal(leftCanonical, expected);
  assert.equal(rightCanonical, expected);
  assert.deepEqual(canonicalPayloadBytes(left), canonicalPayloadBytes(right));
  assert.equal(decoder.decode(canonicalPayloadBytes(left)), expected);
});

test("truncated responses hash only the capped bytes and are never reported complete", async () => {
  const { privateKey } = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const oversizedBody = new Uint8Array(MAX_BODY_BYTES + 7);
  oversizedBody.fill(0x61);
  oversizedBody.fill(0x62, MAX_BODY_BYTES);

  const attestation = await createByteObservationAttestation({
    url: "https://example.test/oversized",
    signingKey: privateKey,
    kid: "test-key-1",
    now: () => new Date("2026-06-14T12:00:00.000Z"),
    idGenerator: () => "WA-truncated",
    fetcher: async () =>
      new Response(oversizedBody, {
        status: 200,
        headers: {
          "Content-Type": "application/octet-stream",
        },
      }),
  });
  const expectedPrefixDigest = await crypto.subtle.digest(
    "SHA-256",
    oversizedBody.slice(0, MAX_BODY_BYTES),
  );

  assert.equal(attestation.payload.body.bytes_hashed, MAX_BODY_BYTES);
  assert.equal(attestation.payload.body.truncated, true);
  assert.equal(attestation.payload.body.complete_body_observed, false);
  assert.equal(
    attestation.payload.body.sha256_hex,
    toHex(new Uint8Array(expectedPrefixDigest)),
  );
});

test("rejects non-HTTPS URLs, URLs with userinfo, and overlong URLs", async () => {
  const { privateKey } = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  const baseOptions = {
    signingKey: privateKey,
    kid: "test-key-1",
    fetcher: async () => {
      throw new Error("fetcher should not be called for rejected URLs");
    },
  };

  await assert.rejects(
    () =>
      createByteObservationAttestation({
        ...baseOptions,
        url: "http://example.test/not-allowed",
      }),
    /HTTPS/,
  );
  await assert.rejects(
    () =>
      createByteObservationAttestation({
        ...baseOptions,
        url: "https://user:pass@example.test/not-allowed",
      }),
    /userinfo/,
  );
  await assert.rejects(
    () =>
      createByteObservationAttestation({
        ...baseOptions,
        url: `https://example.test/${"a".repeat(2048)}`,
      }),
    /2048/,
  );
});

function base64UrlToBytes(value) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return new Uint8Array(Buffer.from(padded, "base64"));
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
