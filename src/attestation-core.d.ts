export const MAX_BODY_BYTES: number;
export const HUMAN_NOTICE: string;

export class AttestationCoreError extends Error {
  code: string;
  constructor(message: string, code: string);
}

export function validateObservationUrl(inputUrl: unknown): string;

export function importSigningKeyFromEnv(
  env: unknown,
  envVarName?: string,
  cryptoImpl?: Crypto,
): Promise<CryptoKey>;

export function createByteObservationAttestation(options: {
  url: string;
  signingKey: CryptoKey;
  kid: string;
  fetcher?: typeof fetch;
  cryptoImpl?: Crypto;
  now?: () => Date;
  idGenerator?: () => string;
}): Promise<Record<string, unknown>>;
