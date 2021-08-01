# Oautter

OAuth 2.0 compliant server.

PS: Pronounced *otter*.

## Configuration

The server requires some basic configuration to run. These can be passed as environment variables.

|Variable        |Required|Default|Example                                      |
|----------------|--------|-------|---------------------------------------------|
|PORT            |NO      |3000   |                                             |
|AUTH_EXPIRATION |NO      |10     |                                             |
|TOKEN_EXPIRATION|NO      |30     |                                             |
|REGION          |YES     |       |ap-south-1                                   |
|REDIS_HOST      |YES     |       |localhost                                    |
|CODE_SALT       |YES     |       |A random sequence of alphanumeric characters.|
|TOKEN_SALT      |YES     |       |A random sequence of alphanumeric characters.|
|PRIV_KEY        |YES     |       |RSA Private Key                              |

## Supported OAuth 2.0 Flows

1. [Authorization Code Flow with PKCE](AUTHORIZATION-CODE-PKCE.md)