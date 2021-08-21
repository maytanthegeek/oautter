import { MongoClient, Db } from 'mongodb';

export default class UserService {
  client: Db;

  tableName = config.USER_TABLE;

  constructor() {
    const mongoClient = new MongoClient(config.MONGO_URL);
    mongoClient.connect().then(() => {
      this.client = mongoClient.db('oauth');
    });
  }

  getUser = async (userId: string) => {
    const params = { userId };

    const response = await this.client.collection(this.tableName).findOne(params, {
      projection: { _id: 0 },
    });

    return response;
  }

  getUserWithoutPassword = async (userId: string) => {
    const params = { userId };

    const response = await this.client.collection(this.tableName).findOne(params, {
      projection: { _id: 0, password: 0 },
    });

    return response;
  }
}
