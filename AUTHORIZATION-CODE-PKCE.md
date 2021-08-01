## Authorization Code Flow with PKCE

### STEP 1: Authentication 

The flow starts with the client redirecting user to autorization page with required parameters.
The values for these parameters should be same for executing this flow:
* `response_type = code`
* `scope = openid+profile+email+address+phone`

The user is presented with a login page to authenticate with username and password. After user finishes logging in, they are redirected to the `redirect_url` with the the authorization code. This code will be valid for a maximum of 10 mins.

NOTE: Make sure after generating code_challenge in base64, you replace `+` with `-` and remove all `=` from the string.

### STEP 2: Getting the Access Token

The client application now sends a token request containing the original random string (not hashed and base64 encoded) to the server for getting the access token.
The values for these parameters should be same for executing this flow:
* `grant_type = authorization_code`

2 tokens are returned:
1. `access_token`: To be used for requesting resources and checking validation. This token is valid for 10 mins.
2. `refresh_token`: This is used to get new `access_token` when the expire. This has a much longer validity. If this expires(Error code 401) then the user needs to repeat the whole process again.

The access_token is a `Bearer` token.

### STEP 3: Refreshing the access_token

To get new `access_token` you have to use the same token request as above but with `refresh_token` and
* `grant_type = refresh_token`

The response is the same as above but with a new token.