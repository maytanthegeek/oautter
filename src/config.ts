import { readFileSync } from 'fs';
import { resolve } from 'path';

const privateKey = readFileSync(resolve(__dirname, '../keys/private.pem'), { encoding: 'utf8' });
const publicKey = readFileSync(resolve(__dirname, '../keys/public.pem'), { encoding: 'utf8' });
const jsks = readFileSync(resolve(__dirname, '../keys/public.json'), { encoding: 'utf8' });

const configuration = {
  ENV: process.env.NODE_ENV || 'development',
  PRIVATE_KEY: privateKey,
  PUBLIC_KEY: publicKey,
  JWKS: JSON.parse(jsks),
  PORT: Number(process.env.PORT) || 3000,
  MONGO_URL: process.env.MONGO_URL || 'mongodb://root:root@localhost:27017',
  CLIENT_TABLE: process.env.CLIENT_TABLE || 'clients',
  USER_TABLE: process.env.USER_TABLE || 'users',
  REDIS_HOST: process.env.REDIS_HOST || 'localhost',
  LOG_LEVEL: process.env.NODE_ENV === 'production' ? 'info' : 'trace',
  ISSUER: process.env.ISSUER || 'https://auth.example.com',
  AUTH_EXPIRATION: Number(process.env.AUTH_EXPIRATION) || 10,
  TOKEN_EXPIRATION: Number(process.env.TOKEN_EXPIRATION) || 10,
  TOKEN_SALT: process.env.TOKEN_SALT || 'secretfortokengeneration',
  CODE_SALT: process.env.CODE_SALT || 'secretfortokengeneration',
};

global.config = configuration;
export default configuration;
