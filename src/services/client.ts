import { MongoClient, Db } from 'mongodb';

export default class ClientService {
  client: Db;

  tableName = config.CLIENT_TABLE;

  constructor() {
    const mongoClient = new MongoClient(config.MONGO_URL);
    mongoClient.connect().then(() => {
      this.client = mongoClient.db('oauth');
    });
  }

  getClient = async (clientId: string) => {
    const params = { clientId };

    const response = await this.client.collection(this.tableName).findOne(params);

    return response;
  }
}
