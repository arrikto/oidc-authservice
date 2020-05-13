# Logout

After the AuthService authenticates users with an IdP, it tracks the user's
status by:
* Issuing a session cookie to be stored in the user's browser.
* Storing the IDToken, access token and refresh token in the AuthService's
  database.

The `/logout` endpoint provides a logout functionality from the AuthService.
On logout, the AuthService will:
1. Revoke the access/refresh tokens at the IdP (if the IdP provides a 
   `revocation_endpoint` in the discovery document). Token revocation is
   described in [RFC-7009](https://tools.ietf.org/html/rfc7009). The tokens are
   stored in the user's session in the backend and never reach the browser.
2. Delete the user's session from the database.
