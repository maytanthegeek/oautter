# Oautter

OAuth 2.0 compliant server.

PS: Pronounced *otter*.

## Configuration

The server requires some basic configuration to run. These can be passed as environment variables.

|Variable        |Required|Default|Example                                      |
|----------------|--------|-------|---------------------------------------------|
|PORT            |NO      |3000   |                                             |
|MONGO_URL       |YES     |       |mongodb://root:root@localhost:27017          |
|CLIENT_TABLE    |NO      |clients|                                             |
|USER_TABLE      |NO      |users  |                                             |
|REDIS_HOST      |YES     |       |localhost                                    |
|ISSUER          |YES     |       |https://auth.example.com                     |
|AUTH_EXPIRATION |NO      |10     |                                             |
|TOKEN_EXPIRATION|NO      |10     |                                             |
|TOKEN_SALT      |YES     |       |A random sequence of alphanumeric characters.|
|CODE_SALT       |YES     |       |A random sequence of alphanumeric characters.|

## Supported OAuth 2.0 Flows

1. [Authorization Code Flow with PKCE](AUTHORIZATION-CODE-PKCE.md)

## Work In Progress

- [x] Userinfo controller
- [x] Access token introspection 
- [ ] Refresh token introspection
- [ ] Revoke access token
- [ ] Revoke refresh token
- [ ] Logout
