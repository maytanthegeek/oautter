import { Request, Response, Router } from 'express';
import jwt from 'jsonwebtoken';
import HTTPError from '../services/http-error';

/**
 * Express controller for user info APIs.
 */
export default class Verification {
  /** Express router for this controller. */
  router = Router();

  /** JWKS for the server. */
  keySet = config.JWKS;

  /** Service for performing user related operations. */

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
    this.router.get('/keys', this.getKeys);
    this.router.post('/introspect', this.introspect);
  }

  private verifyToken = async (token: string) => new Promise<object>((resolve, reject) => {
    jwt.verify(token, config.PUBLIC_KEY, { algorithms: ['RS256'] }, (err, decodedToken) => {
      if (err) reject();
      if (typeof decodedToken !== 'object') reject();
      resolve(decodedToken);
    });
  });

  private getKeys = async (request: Request, response: Response) => {
    const jwks = [{
      ...this.keySet,
      status: 'ACTIVE',
    }];
    return response.send(jwks);
  }

  private introspect = async (request: Request, response: Response) => {
    const { token, token_type_hint: tokenTypeHint } = request.body;
    try {
      if (!token || !tokenTypeHint) {
        throw new HTTPError(400, 'invalid_request', 'Invalid or malformed request structure.');
      }

      let result = {
        active: false,
      };
      switch (tokenTypeHint) {
        case 'access_token':
          await this.verifyToken(token).then((decodedToken) => {
            if (decodedToken) {
              result = {
                ...decodedToken,
                active: true,
              };
            }
          }).catch();
          break;
        case 'refresh_token': break;
        default: throw new HTTPError(400, 'invalid_request', 'Invalid or malformed request structure.');
      }

      return response.send(result);
    } catch (err) {
      if (err instanceof HTTPError) {
        const params = {
          error: err.message,
          error_description: err.description,
        };
        return response.status(err.code).send(params);
      }
      const params = {
        error: 'server_error',
      };
      return response.status(500).send(params);
    }
  }
}
