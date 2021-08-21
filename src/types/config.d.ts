type ConfigType = {
  ENV: string,
  PRIVATE_KEY: string,
  PUBLIC_KEY: string,
  JWKS: {
    alg: string,
    e: string,
    n: string,
    kid: string,
    kty: string,
    use: string,
  },
  PORT: number,
  MONGO_URL: string,
  CLIENT_TABLE: string,
  USER_TABLE: string
  REDIS_HOST: string,
  LOG_LEVEL: string,
  ISSUER: string,
  AUTH_EXPIRATION: number,
  TOKEN_EXPIRATION: number,
  TOKEN_SALT: string,
  CODE_SALT: string,
};