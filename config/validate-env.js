export function validateEnv() {
  const required = [
    "UPSTASH_REDIS_REST_URL",
    "UPSTASH_REDIS_REST_TOKEN",
    "HMAC_SECRET",
    "TOKEN_SALT"
  ];

  for (const key of required) {
    if (!process.env[key]) {
      throw new Error(`Missing ENV: ${key}`);
    }
  }
}
