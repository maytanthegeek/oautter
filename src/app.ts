import compression from 'compression';
import cors from 'cors';
import express from 'express';
import expressPino from 'express-pino-logger';
import path from 'path';
import pino from 'pino';
import Authentication from './controllers/authentication';
import Authorization from './controllers/authorization';
import ServerMeta from './controllers/server-meta';
import UserInfo from './controllers/user-info';
import Verification from './controllers/verification';

/**
 * Main class to create the express server.
 */
class App {
  /** The express server object. */
  app: express.Application;

  /**
   * Creates the express server.
   * @param controllers List of all controllers objects to attach to the server.
   * @param port The port number to expose the server on.
   */
  constructor(controllers: any[]) {
    this.app = express();
    this.app.set('views', path.join(__dirname, './public/views'));
    this.app.set('view engine', 'ejs');

    this.initializeMiddlewares();
    this.initializeControllers(controllers);
  }

  /**
   * Method to attach additional middlewares to the express server.
   */
  private initializeMiddlewares() {
    this.app.use(compression());
    this.app.use(cors());
    this.app.use(
      express.urlencoded({
        extended: false,
      }),
    );
    this.app.use(express.json());
    const basicPinoLogger = pino({
      level: config.LOG_LEVEL,
      prettyPrint: config.ENV !== 'production',
      formatters: {
        level(label) {
          return { level: label };
        },
      },
    });
    this.app.use(
      expressPino({ logger: basicPinoLogger }),
    );
  }

  /**
   * Attaches the controllers to the appropriate route in the server.
   * @param controllers List of all controller objects to attach to the server.
   */
  private initializeControllers(controllers: any[]) {
    controllers.forEach((controller) => {
      this.app.use('/oauth2', controller.router);
    });
  }
}

const { ISSUER, AUTH_EXPIRATION, TOKEN_EXPIRATION } = config;
const server = new App([
  new Authentication(AUTH_EXPIRATION),
  new Authorization(ISSUER, AUTH_EXPIRATION, TOKEN_EXPIRATION),
  new UserInfo(),
  new ServerMeta(ISSUER),
  new Verification(),
]);

export default server;
