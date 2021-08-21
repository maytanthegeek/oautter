import { Request, Response, Router } from 'express';

/**
 * Express controller for user info APIs.
 */
export default class ServerMeta {
  /** Express router for this controller. */
  router = Router();

  /** The issuer identification of the tokens. */
  private ISSUER: string;

  /**
   * Creates the controller and adds routes.
   */
  constructor(issuer: string) {
    this.ISSUER = issuer;
    this.initializeRoutes();
  }

  /**
   * Initializes routes with their handlers.
   */
  private initializeRoutes() {
    this.router.get('/.well-known/oauth-authorization-server', this.getOauthServerMeta);
    this.router.get('/.well-known/openid-configuration', this.getOpenIDServerMeta);
  }

  private getOauthServerMeta = async (request: Request, response: Response) => {
    const serverMeta = {
      issuer: this.ISSUER,
      authorization_endpoint: `${this.ISSUER}/oauth2/authorize`,
      token_endpoint: `${this.ISSUER}/oauth2/token`,
      registration_endpoint: `${this.ISSUER}/oauth2/register`,
      jwks_uri: `${this.ISSUER}/oauth2/keys`,
      response_types_supported: [
        'code',
        'token',
      ],
      response_modes_supported: [
        'query',
      ],
      grant_types_supported: [
        'authorization_code',
        'refresh_token',
      ],
      subject_types_supported: [
        'public',
      ],
      scopes_supported: [
        'openid',
        'profile',
        'email',
        'address',
        'phone',
      ],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'none',
      ],
      claims_supported: [
        'string',
      ],
      code_challenge_methods_supported: [
        'S256',
      ],
      introspection_endpoint: `${this.ISSUER}/oauth2/introspect`,
      introspection_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'none',
      ],
      revocation_endpoint: `${this.ISSUER}/oauth2/revoke`,
      revocation_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'none',
      ],
      end_session_endpoint: `${this.ISSUER}/oauth2/logout`,
      request_parameter_supported: true,
    };
    return response.send(serverMeta);
  }

  private getOpenIDServerMeta = async (request: Request, response: Response) => {
    const serverMeta = {
      issuer: this.ISSUER,
      authorization_endpoint: `${this.ISSUER}/oauth2/authorize`,
      token_endpoint: `${this.ISSUER}/oauth2/token`,
      registration_endpoint: `${this.ISSUER}/oauth2/register`,
      jwks_uri: `${this.ISSUER}/oauth2/keys`,
      response_types_supported: [
        'code',
        'token',
      ],
      response_modes_supported: [
        'query',
      ],
      grant_types_supported: [
        'authorization_code',
        'refresh_token',
      ],
      subject_types_supported: [
        'public',
      ],
      scopes_supported: [
        'openid',
        'profile',
        'email',
        'address',
        'phone',
      ],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'none',
      ],
      claims_supported: [
        'string',
      ],
      code_challenge_methods_supported: [
        'S256',
      ],
      introspection_endpoint: `${this.ISSUER}/oauth2/introspect`,
      introspection_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'none',
      ],
      revocation_endpoint: `${this.ISSUER}/oauth2/revoke`,
      revocation_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'none',
      ],
      end_session_endpoint: `${this.ISSUER}/oauth2/logout`,
      request_parameter_supported: true,
    };
    return response.send(serverMeta);
  }
}
