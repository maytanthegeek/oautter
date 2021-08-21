import { Request, Response, Router } from 'express';
import jwt from 'jsonwebtoken';
import * as redisService from '../services/redis';
import UserService from '../services/user';

/**
 * Express controller for user info APIs.
 */
export default class UserInfo {
  /** Express router for this controller. */
  router = Router();

  /** Service for performing user related operations. */
  private userService = new UserService();

  /**
   * Creates the controller and adds routes.
   */
  constructor() {
    this.initializeRoutes();
  }

  /**
   * Initializes routes with their handlers.
   */
  private initializeRoutes() {
    this.router.get('/userinfo', this.getUserInfo);
  }

  /**
   * Returns all the relevant information about a specific user.
   * @param request Express request object.
   * @param response Express response object.
   */
  private getUserInfo = async (request: Request, response: Response) => {
    // Authentication
    const token = request.headers.authorization ? request.headers.authorization.replace('Bearer ', '') : '';
    const key = config.PUBLIC_KEY;
    if (!key) {
      return response.status(500).send();
    }
    let decodedToken: jwt.JwtPayload;
    try {
      decodedToken = jwt.verify(token, key, { algorithms: ['RS256'] }) as jwt.JwtPayload;

      if (typeof decodedToken !== 'object') {
        const up = new Error('Token Invalid');
        throw up;
      }
    } catch (err) {
      return response.status(401)
        .set('WWW-Authenticate', 'Bearer error="invalid_token", error_description="The access token is invalid"')
        .send();
    }

    // Get user info
    const stringifiedUserInfo = await redisService.getAsync(decodedToken.uid) || '';
    try {
      const user = stringifiedUserInfo !== ''
        ? JSON.parse(stringifiedUserInfo)
        : await this.userService.getUserWithoutPassword(decodedToken.uid);

      const { userId, ...userDetails } = user;

      return response.send({
        sub: userId,
        ...userDetails,
      });
    } catch (err) {
      return response.status(403).send();
    }
  }
}
