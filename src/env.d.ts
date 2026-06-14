interface Env {
  WEB_ATTESTATION_ED25519_PRIVATE_JWK: string;
  CDP_API_KEY_ID: string;
  CDP_API_KEY_SECRET: string;
}

declare module "*.json" {
  const value: Record<string, unknown>;
  export default value;
}
