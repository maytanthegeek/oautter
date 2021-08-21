import * as bcrypt from 'bcryptjs';
import { Request, Response, Router } from 'express';
import UserService from '../services/user';
import * as redisService from '../services/redis';

/**
 * Express controller for user login view.
 */
export default class Authentication {
  /** Express router for this controller. */
  router = Router();

  /** Service for performing user related operations. */
  private userService = new UserService();

  /** Number of minutes after which authorization code expires. */
  private AUTH_EXPIRATION: number;

  /**
   * Creates the controller and adds routes.
   */
  constructor(authExpiration: number) {
    this.AUTH_EXPIRATION = authExpiration;
    this.initializeRoutes();
  }

  /**
   * Initializes routes with their handlers.
   */
  private initializeRoutes() {
    this.router.get('/login', this.renderAuthenticationUI);
    this.router.post('/login', this.checkCredentials);
  }

  /**
   * Helper function to verify if the password matches for the provided user.
   * @param userId Unique id of the user.
   * @param password Encrypted password for the user.
   */
  private verifyUserCredentials = async (userId: string, password: string): Promise<{
    valid: boolean,
    user: any,
  }> => {
    try {
      const user = await this.userService.getUser(userId);
      const valid = user ? await bcrypt.compare(password, user.password) : false;
      delete user.password;
      return { valid, user };
    } catch (err) {
      return { valid: false, user: {} };
    }
  }

  /**
   * Renders the login view for an authorization request.
   * @param request Express request object.
   * @param response Express response object.
   */
  private renderAuthenticationUI = (request: Request, response: Response) => response.render('login', { session: request.query.session });

  /**
   * API to check user credentials.
   * @param request Express router request object.
   * @param response Express router response object.
   */
  private checkCredentials = async (request: Request, response: Response) => {
    const { userid, password, session } = request.body;
    try {
      if (!userid || !password || !session) {
        const up = new Error('Parameter error');
        throw up;
      }

      if (typeof userid !== 'string' || typeof password !== 'string' || typeof session !== 'string') {
        const up = new Error('Parameter error');
        throw up;
      }

      const { valid, user } = await this.verifyUserCredentials(userid, password);

      if (!valid) {
        const up = new Error('Credentials error');
        throw up;
      }

      await redisService.setAsync(user.userId, JSON.stringify(user), this.AUTH_EXPIRATION * 60000);
      await redisService.setAsync(`${session}_user`, JSON.stringify(user), 60000);
      return response.send({});
    } catch (err) {
      request.log.error(err);
      const params = {
        error: 'invalid_request',
      };
      return response.status(400).send(params);
    }
  }
}
