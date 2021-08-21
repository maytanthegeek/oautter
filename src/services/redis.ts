import { promisify } from 'util';
import { createClient, RedisClient } from 'redis';

const redis: RedisClient = createClient({ host: config.REDIS_HOST });

export const getAsync = promisify(redis.get).bind(redis);

export const setAsync = async (key: string, value: string, expire?: number) => {
  const baseSetAsync = promisify(redis.set).bind(redis);
  try {
    if (expire === undefined) {
      await baseSetAsync(key, value);
    } else {
      await baseSetAsync(key, value, 'PX', expire);
    }
  } catch (err) {
    return false;
  }
  return true;
};

export const deleteAsync = async (key: string) => redis.del(key);
