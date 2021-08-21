import { createHash, createHmac } from 'crypto';
import { Request, Response, Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';
import ClientService from '../services/client';
import HTTPError from '../services/http-error';
import * as redisService from '../services/redis';

/**
 * Express controller for authorization endpoints.
 */
export default class Authorization {
  /** Express router for this controller. */
  router = Router();

  /** List of scopes supported by server. */
  private SCOPES = ['openid', 'email', 'phone', 'profile'];

  /** Service for performing client application related operations. */
  private clientService = new ClientService();

  /** Number of minutes after which authorization code expires. */
  private AUTH_EXPIRATION: number;

  /** The issuer identification of the tokens. */
  private ISSUER: string;

  /** Number of minutes after which access token expires. */
  private TOKEN_EXPIRATION: number;

  private CODE_SALT = config.CODE_SALT;

  private TOKEN_SALT = config.TOKEN_SALT;

  private PRIVATE_KEY = config.PRIVATE_KEY;

  private keyId = config.JWKS.kid;

  /**
   * Creates the controller and adds routes.
   */
  constructor(issuer: string, authExpiration: number, tokenExpiration: number) {
    this.AUTH_EXPIRATION = authExpiration;
    this.ISSUER = issuer;
    this.TOKEN_EXPIRATION = tokenExpiration;
    this.initializeRoutes();
  }

  /**
   * Initializes routes with their handlers.
   */
  private initializeRoutes() {
    this.router.get('/authorize', this.generateAuthPage);
    this.router.post('/callback', this.generateAuthCode);
    this.router.post('/token', this.issueToken);
    this.router.post('/revoke', this.issueToken);
    this.router.post('/logout', this.issueToken);
  }

  /**
   * Helper function to verify if client information exists in the database.
   * @param clientId Unique id for every client application.
   * @param redirectUrl The callback URL of the client to which this server redirects the user to.
   */
  private verifyClientInfo = async (clientId: string, redirectUrl: string) => {
    const clientInfo = await this.clientService.getClient(clientId);
    return clientInfo ? (clientInfo.redirectUrl as String[]).includes(redirectUrl) : false;
  }

  /**
   * Helper function to verify if client secret matches to the client id provided.
   * @param clientId Unique id for every client application.
   * @param clientSecret The secret string issued to every client application.
   */
  private verifyClientSecret = async (clientId: string, clientSecret: string) => {
    const clientInfo = await this.clientService.getClient(clientId);
    return clientInfo ? (clientInfo.clientSecret === clientSecret) : false;
  }

  /**
   * Helper function to verify if the challenge string provided in authorization request matches
   * the plain verifier.
   * @param authorizationCode Short lived code generated during authorization request.
   * @param clientId Unique id for the client application.
   * @param redirectUrl The callback URL of the client to which this server redirects the user to.
   * @param codeVerifier Plain string to be matched with the encrypted challenge string.
   */
  private verifyAuthorizationCode = async (
    authorizationCode: string,
    redirectUrl: string,
    codeVerifier?: string,
  ) => {
    const codeInfoStringified = await redisService.getAsync(authorizationCode) || '{}';
    const codeInfo = JSON.parse(codeInfoStringified);

    if (redirectUrl !== codeInfo.redirectUrl) {
      return undefined;
    }

    if (Date.now() > codeInfo.exp) {
      return undefined;
    }

    if (typeof codeVerifier === 'string') {
      const codeChallenge = this.generateCodeChallenge(codeVerifier);
      if (codeChallenge !== codeInfo.codeChallenge) {
        return undefined;
      }
    }

    await redisService.deleteAsync(authorizationCode);
    return codeInfo.userId;
  }

  /**
   * Helper function to verify if the client is valid and if refresh token has expired.
   * @param clientId Unique id for the client application.
   * @param refreshToken Long lived token to generate new access tokens for a client.
   * @param redirectUrl The callback URL of the client to which this server redirects the user to.
   */
  private verifyRefreshToken = async (
    clientId: string,
    refreshToken: string,
    redirectUrl: string,
  ) => {
    const tokenInfoStringified = await redisService.getAsync(refreshToken) || '';
    const tokenInfo = JSON.parse(tokenInfoStringified);

    if (clientId !== tokenInfo.clientId || redirectUrl !== tokenInfo.redirectUrl) {
      return undefined;
    }

    if (Date.now() > tokenInfo.exp) {
      return undefined;
    }

    return tokenInfo.userId;
  }

  /**
   * Helper function to generate authorization code and cache it for code OAuth flow.
   * @param clientId Unique id for the client application.
   * @param redirectUrl The callback URL of the client to which this server redirects the user to.
   * @param userId Unique id of the user.
   * @param salt A random 32 byte HEX sequence.
   * @param codeChallenge SHA256 encrypted challenge string.
   */
  private generateAuthorizationCode = (
    clientId: string,
    redirectUrl: string,
    userId: string,
    codeChallenge?: string,
  ) => {
    const EXPIRY = Date.now() + this.AUTH_EXPIRATION * 60000;
    const data = JSON.stringify({
      clientId,
      redirectUrl,
      exp: EXPIRY,
    });

    const authorizationCode = createHmac('sha256', this.CODE_SALT)
      .update(data)
      .digest('hex');

    const cachedData = JSON.stringify({
      clientId,
      redirectUrl,
      userId,
      codeChallenge,
      exp: EXPIRY,
    });

    redisService.setAsync(authorizationCode, cachedData, this.AUTH_EXPIRATION * 60000);
    return authorizationCode;
  }

  /**
   * Helper function generate SHA256 encrypted string from plaintext.
   * @param codeVerifier Plain text string.
   */
  private generateCodeChallenge = (codeVerifier: string) => {
    const hash = createHash('sha256').update(codeVerifier).digest('base64');
    return hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Helper function to generate a long lived refresh token and chache it.
   * @param clientId Unique id for the client application.
   * @param redirectUrl The callback URL of the client to which this server redirects the user to.
   * @param userId Unique id of the user.
   */
  private generateRefreshToken = (
    clientId: string,
    redirectUrl: string,
    userId: string,
  ) => {
    const EXPIRY = 7 * 24 * 60 * 60000;
    const data = JSON.stringify({
      clientId,
      redirectUrl,
      exp: Date.now() + EXPIRY,
    });

    const refreshToken = createHmac('sha256', this.TOKEN_SALT)
      .update(data)
      .digest('hex');

    const cachedData = JSON.stringify({
      clientId,
      redirectUrl,
      userId,
      exp: EXPIRY,
    });

    redisService.setAsync(refreshToken, cachedData, EXPIRY);
    return refreshToken;
  }

  /**
   * Helper function to generate access token for the user.
   * @param userId Unique id of the user.
   */
  private generateAccessToken = (clientId: string, userId: string) => {
    const payload = {
      cid: clientId,
      iss: this.ISSUER,
      uid: userId,
    };

    const privateKey = this.PRIVATE_KEY;
    if (privateKey) {
      const accessToken = jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        expiresIn: `${this.TOKEN_EXPIRATION}m`,
        keyid: this.keyId,
      });
      return accessToken;
    }
    return 'INVALID_TOKEN_PRODUCED';
  }

  /**
   * Helper function to generate a response for token API when grant type is code.
   * @param code Authorizxation code generate during authorization request.
   * @param clientId Unique id for the client application.
   * @param clientSecret A secret issued to the client application.
   * @param codeVerifier Plaintext string from which the encrypted challenge string is generated.
   * @param redirectUrl The callback URL of the client to which this server redirects the user to.
   */
  private generateAuthCodeTokenResponse = async (
    code: string,
    clientId: string,
    clientSecret: string,
    codeVerifier: string,
    redirectUrl: string,
  ) => {
    const xor = (a: boolean, b: boolean): boolean => ((a || b) && !(a && b));
    if (!code || !xor((!!clientId && !!clientSecret), !!codeVerifier) || !redirectUrl) {
      const up = new HTTPError(400, 'invalid_request', 'Parameter missing.');
      throw up;
    }
    if (
      typeof code !== 'string'
      || typeof redirectUrl !== 'string'
    ) {
      const up = new HTTPError(400, 'invalid_request', 'Unsupported parameter type.');
      throw up;
    }

    if ((!!clientSecret && typeof clientSecret === 'string') && (!!clientId && typeof clientId === 'string')) {
      if (!await this.verifyClientSecret(clientId, clientSecret)) {
        const up = new HTTPError(401, 'invalid_client', 'No client credentials found.');
        throw up;
      }
    }

    const userId = await this.verifyAuthorizationCode(code, redirectUrl, codeVerifier);
    if (!userId) {
      const up = new HTTPError(400, 'invalid_grant', 'Invalid conbination of code and redirect_url or code expired.');
      throw up;
    }

    const accessToken = this.generateAccessToken(clientId, userId);
    const refreshToken = this.generateRefreshToken(
      clientId,
      redirectUrl,
      userId,
    );
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: this.TOKEN_EXPIRATION * 60,
    };
  }

  /**
   * Helper function to generate a response for token API when grant type is refresh_type.
   * @param clientId Unique id for the client application.
   * @param refreshToken Long lived token to generate new access tokens for a client.
   * @param redirectUrl The callback URL of the client to which this server redirects the user to.
   */
  private generateRefreshTokenResponse = async (
    clientId: string,
    refreshToken: string,
    redirectUrl: string,
  ): Promise<{
    'access_token': string,
    'refresh_token': string,
    'token_type': string,
    'expires_in': number,
  }> => {
    if (!clientId || !refreshToken || !redirectUrl) {
      const up = new Error('Parameter error');
      throw up;
    }
    if (
      typeof clientId !== 'string'
      || typeof refreshToken !== 'string'
      || typeof redirectUrl !== 'string'
    ) {
      const up = new Error('Parameter error');
      throw up;
    }

    const userId = await this.verifyRefreshToken(clientId, refreshToken, redirectUrl);
    if (!userId) {
      const up = new Error('Permission error');
      throw up;
    }

    const accessToken = this.generateAccessToken(clientId, userId);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: this.TOKEN_EXPIRATION * 60,
    };
  }

  /**
   * API to redirect for authenticating user and take permission for profile access.
   * @param request Express router request object.
   * @param response Express router response object.
   */
  private generateAuthPage = async (request: Request, response: Response) => {
    const {
      response_type: responseType,
      client_id: clientId,
      redirect_uri: redirectUrl,
      code_challenge: codeChallenge,
      state,
      scope,
    } = request.query;
    try {
      // Request must have valid clientId and redirectUrl. If not, throw error but DO NOT REDIRECT.
      if (!clientId || !redirectUrl) {
        const up = new HTTPError(400, 'invalid_request', 'Missing or invalid parameters.');
        throw up;
      }

      if (typeof clientId !== 'string' || typeof redirectUrl !== 'string') {
        const up = new HTTPError(400, 'invalid_request', 'Missing or invalid parameters.');
        throw up;
      }

      if (!await this.verifyClientInfo(clientId, redirectUrl)) {
        const up = new HTTPError(400, 'invalid_request', 'Missing or invalid parameters.');
        throw up;
      }

      // Checking for validity of all other params.
      if (!responseType || !scope) {
        const up = new HTTPError(302, 'invalid_request', 'Missing or invalid parameters.');
        throw up;
      }

      if (
        typeof responseType !== 'string'
        || typeof clientId !== 'string'
        || typeof redirectUrl !== 'string'
        || typeof scope !== 'string'
      ) {
        const up = new HTTPError(302, 'invalid_request', 'Unsupported parameter type.');
        throw up;
      }

      if (responseType !== 'code') {
        const up = new HTTPError(302, 'unsupported_response_type', 'Provided response_type is not supported.');
        throw up;
      }

      const scopes = scope.split(' ');
      if (!(scopes.includes('openid') && scopes.every((scp) => this.SCOPES.includes(scp)))) {
        const up = new HTTPError(302, 'invalid_scope', 'One or more scopes not supported.');
        throw up;
      }

      // All params OK. Start the authentication process.
      const params = {
        responseType,
        clientId,
        redirectUrl,
        oauthScope: scope,
        ...(codeChallenge && (typeof codeChallenge === 'string') && { codeChallenge }),
        ...(state && (typeof state === 'string') && { state }),
      };

      const uuid = uuidv4();

      await redisService.setAsync(`${uuid}_auth`, JSON.stringify(params), 60000);

      return response.render('callback', { session: uuid });
    } catch (err) {
      if (err instanceof HTTPError) {
        const params = {
          error: err.message,
          error_description: err.description,
        };

        switch (err.code) {
          case 302:
            return response.redirect(`${redirectUrl}?${new URLSearchParams(params).toString()}`);
          default:
            return response.status(err.code).send(params);
        }
      }

      request.log.error(err);

      const params = {
        error: 'server_error',
      };

      return response.status(500).send(params);
    }
  }

  /**
   * API to handle callback from authentication server.
   * @param request Express router request object.
   * @param response Express router response object.
   */
  private generateAuthCode = async (request: Request, response: Response) => {
    const { session } = request.body;
    let redirectUrl: string;
    try {
      const authDataStringified = await redisService.getAsync(`${session}_auth`);
      const userDataStringified = await redisService.getAsync(`${session}_user`);
      const authData = JSON.parse(authDataStringified);
      const userData = JSON.parse(userDataStringified);

      if (!authData || !userData) {
        const up = new HTTPError(403, 'access_denied', 'The request was denied by the authentication server.');
        throw up;
      }

      const { clientId, codeChallenge, redirectUrl: redirectUrlFromAuthData } = authData;
      const { userId } = userData;
      redirectUrl = redirectUrlFromAuthData;

      const code = this.generateAuthorizationCode(clientId, redirectUrl, userId, codeChallenge);
      return response.redirect(`${redirectUrl}?code=${code}`);
    } catch (err) {
      if (err instanceof HTTPError) {
        const params = {
          error: err.message,
          error_description: err.description,
        };

        switch (err.code) {
          case 302:
            return response.redirect(`${redirectUrl}?${new URLSearchParams(params).toString()}`);
          default:
            return response.status(err.code).send(params);
        }
      }

      request.log.error(err);

      const params = {
        error: 'server_error',
      };

      return response.status(500).send(params);
    }
  }

  /**
   * API to validate grant then issue access token according to that.
   * @param request Express router request object.
   * @param response Express router response object.
   */
  private issueToken = async (request: Request, response: Response) => {
    const {
      grant_type: grantType,
      code,
      code_verifier: codeVerifier,
      refresh_token: refreshToken,
      redirect_uri: redirectUrl,
    } = request.body;
    let {
      client_id: clientId,
      client_secret: clientSecret,
    } = request.body;
    const basicAuth = request.headers.authorization ? request.headers.authorization.replace('Basic ', '') : '';
    if (basicAuth !== '') {
      const decodedBasicAuth = Buffer.from(basicAuth, 'base64').toString('utf8');
      [clientId, clientSecret] = decodedBasicAuth.split(':');
    }
    try {
      let res;
      switch (grantType) {
        case 'authorization_code':
          res = await this.generateAuthCodeTokenResponse(
            code,
            clientId,
            clientSecret,
            codeVerifier,
            redirectUrl,
          );
          return response.send(res);
        case 'refresh_token':
          res = await this.generateRefreshTokenResponse(
            clientId,
            refreshToken,
            redirectUrl,
          );
          return response.send(res);
        default:
          throw new HTTPError(400, 'unsupported_grant_type', 'This grant_type is not supported.');
      }
    } catch (err) {
      request.log.error(err);
      if (err instanceof HTTPError) {
        const params = {
          error: err.message,
          error_description: err.description,
        };
        switch (err.code) {
          case 302:
            return response.redirect(`${redirectUrl}?${new URLSearchParams(params).toString()}`);
          default:
            return response.status(err.code).send(params);
        }
      }
      const params = {
        error: 'server_error',
      };
      return response.redirect(`${redirectUrl}?${new URLSearchParams(params).toString()}`);
    }
  }
}
