export const MAX_URL_CHARS = 2048;
export const MAX_CONTENT_TYPE_CHARS = 512;
export const MAX_BODY_BYTES = 1048576;
export const ATTESTATION_TYPE = "byte_observation.v1";
export const CANONICALIZATION = "RFC8785-JCS";
export const HASH_ALG = "sha-256";
export const HASH_SUBJECT = "response_body_bytes";
export const HUMAN_NOTICE =
  "Byte-observation receipt only. Attests that this endpoint observed the above response at the stated time. No claim as to truth, legitimacy, ownership, or trustworthiness of the content.";

const CONTROL_AND_BIDI_RE =
  /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

export class AttestationCoreError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "AttestationCoreError";
    this.code = code;
  }
}

export function sanitizeForSignedPayload(value, maxChars) {
  return String(value ?? "").replace(CONTROL_AND_BIDI_RE, "").slice(0, maxChars);
}

export function validateObservationUrl(inputUrl) {
  if (typeof inputUrl !== "string") {
    throw new AttestationCoreError("URL must be a string.", "ERR_URL_TYPE");
  }

  if (inputUrl.length > MAX_URL_CHARS) {
    throw new AttestationCoreError(
      `URL exceeds ${MAX_URL_CHARS} characters.`,
      "ERR_URL_TOO_LONG",
    );
  }

  const sanitizedUrl = sanitizeForSignedPayload(inputUrl, MAX_URL_CHARS);
  let parsed;

  try {
    parsed = new URL(sanitizedUrl);
  } catch {
    throw new AttestationCoreError("URL is invalid.", "ERR_URL_INVALID");
  }

  if (parsed.protocol !== "https:") {
    throw new AttestationCoreError(
      "Only HTTPS URLs may be attested.",
      "ERR_URL_NOT_HTTPS",
    );
  }

  if (parsed.username || parsed.password) {
    throw new AttestationCoreError(
      "URLs containing userinfo are rejected.",
      "ERR_URL_USERINFO",
    );
  }

  return sanitizedUrl;
}

export function canonicalizeJcs(value) {
  return serializeJcs(value);
}

export function canonicalPayloadBytes(payload) {
  return new TextEncoder().encode(canonicalizeJcs(payload));
}

export async function importEd25519PrivateKeyFromJwk(
  jwk,
  cryptoImpl = globalThis.crypto,
) {
  const parsed = typeof jwk === "string" ? JSON.parse(jwk) : jwk;
  const { alg, ...keyData } = parsed;
  return cryptoImpl.subtle.importKey(
    "jwk",
    keyData,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

export async function importSigningKeyFromEnv(
  env,
  envVarName = "WEB_ATTESTATION_ED25519_PRIVATE_JWK",
  cryptoImpl = globalThis.crypto,
) {
  const rawJwk = env?.[envVarName];

  if (!rawJwk) {
    throw new AttestationCoreError(
      `Missing Ed25519 signing key environment variable: ${envVarName}.`,
      "ERR_SIGNING_KEY_MISSING",
    );
  }

  return importEd25519PrivateKeyFromJwk(rawJwk, cryptoImpl);
}

export async function createByteObservationAttestation({
  url,
  signingKey,
  kid,
  fetcher = globalThis.fetch,
  cryptoImpl = globalThis.crypto,
  now = () => new Date(),
  idGenerator,
} = {}) {
  const sanitizedUrl = validateObservationUrl(url);

  if (!kid || typeof kid !== "string") {
    throw new AttestationCoreError("kid must be a non-empty string.", "ERR_KID");
  }

  if (!signingKey) {
    throw new AttestationCoreError(
      "An Ed25519 signing key is required.",
      "ERR_SIGNING_KEY_MISSING",
    );
  }

  if (typeof fetcher !== "function") {
    throw new AttestationCoreError("fetcher must be a function.", "ERR_FETCHER");
  }

  const response = await fetcher(sanitizedUrl, {
    method: "GET",
    redirect: "manual",
    headers: {
      "Accept-Encoding": "identity",
    },
  });

  const { bodyBytes, bytesHashed, truncated } = await readBodyPrefix(
    response.body,
    MAX_BODY_BYTES,
  );
  const digest = await cryptoImpl.subtle.digest("SHA-256", bodyBytes);
  const contentType = sanitizeForSignedPayload(
    response.headers.get("content-type") ?? "",
    MAX_CONTENT_TYPE_CHARS,
  );
  const payload = {
    attestation_type: ATTESTATION_TYPE,
    kid,
    attestation_id:
      typeof idGenerator === "function"
        ? idGenerator()
        : generateAttestationId(cryptoImpl),
    observed_at: now().toISOString(),
    canonicalization: CANONICALIZATION,
    request: {
      method: "GET",
      url: sanitizedUrl,
      redirect_policy: "manual_no_follow",
    },
    response: {
      http_status: response.status,
      ok: response.status >= 200 && response.status <= 299,
      content_type: contentType,
    },
    body: {
      hash_alg: HASH_ALG,
      sha256_hex: bytesToHex(new Uint8Array(digest)),
      hash_subject: HASH_SUBJECT,
      bytes_hashed: bytesHashed,
      complete_body_observed: !truncated,
      truncated,
      max_bytes: MAX_BODY_BYTES,
    },
    claims: "none",
    human_notice: HUMAN_NOTICE,
  };
  const signedBytes = canonicalPayloadBytes(payload);
  const signature = await cryptoImpl.subtle.sign(
    { name: "Ed25519" },
    signingKey,
    signedBytes,
  );

  return {
    payload,
    signature: bytesToBase64Url(new Uint8Array(signature)),
    kid,
  };
}

async function readBodyPrefix(stream, maxBytes) {
  if (!stream) {
    return {
      bodyBytes: new Uint8Array(0),
      bytesHashed: 0,
      truncated: false,
    };
  }

  const reader = stream.getReader();
  const chunks = [];
  let bytesHashed = 0;
  let truncated = false;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) {
        break;
      }

      if (!(value instanceof Uint8Array)) {
        throw new AttestationCoreError(
          "Response body stream yielded non-byte data.",
          "ERR_BODY_STREAM",
        );
      }

      if (value.byteLength === 0) {
        continue;
      }

      const remaining = maxBytes - bytesHashed;

      if (remaining <= 0) {
        truncated = true;
        await reader.cancel();
        break;
      }

      if (value.byteLength > remaining) {
        chunks.push(value.slice(0, remaining));
        bytesHashed += remaining;
        truncated = true;
        await reader.cancel();
        break;
      }

      chunks.push(value);
      bytesHashed += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  return {
    bodyBytes: concatUint8Arrays(chunks, bytesHashed),
    bytesHashed,
    truncated,
  };
}

function generateAttestationId(cryptoImpl) {
  const bytes = new Uint8Array(9);
  cryptoImpl.getRandomValues(bytes);
  return `WA-${bytesToBase64Url(bytes)}`;
}

function serializeJcs(value) {
  if (value === null) {
    return "null";
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => serializeJcs(item)).join(",")}]`;
  }

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError("JCS cannot canonicalize non-finite numbers.");
      }
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      const keys = Object.keys(value).sort();
      return `{${keys
        .map((key) => `${JSON.stringify(key)}:${serializeJcs(value[key])}`)
        .join(",")}}`;
    }
    default:
      throw new TypeError(`JCS cannot canonicalize ${typeof value} values.`);
  }
}

function concatUint8Arrays(chunks, totalLength) {
  const output = new Uint8Array(totalLength);
  let offset = 0;

  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return output;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes) {
  let binary = "";

  for (let offset = 0; offset < bytes.byteLength; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
