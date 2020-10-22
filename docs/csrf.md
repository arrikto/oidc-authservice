# CSRF

## Introduction

Cross-Site Request Forgery (CSRF) happens when a malicious website manages to
trick the browser into performing an unintended action on a valid website.

Many websites use cookies to authenticate a user. Cookies are stored in the
browser and are included in every request to the backend. CSRF takes advantage
of requests that change state in the backend.

In the context of the AuthService, which performs login and logout workflows,
we need to protect the user against involuntary logins and logouts.

Here are some attacks that used a CSRF-vulnerable login or logout endpoint:
- https://ngailong.wordpress.com/2017/08/07/uber-login-csrf-open-redirect-account-takeover/
- https://whitton.io/articles/uber-turning-self-xss-into-good-xss/
- https://blog.jeremiahgrossman.com/2008/09/i-used-to-know-what-you-watched-on.html

For CSRF mitigation, see the excellent OWASP CSRF cheat sheet:
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

## Login CSRF

Login CSRF occurs when an attacker crafts a special URL which will login the
user as the attacker's account. In the context of OIDC, the attacker can do this
by logging in with their account at the OIDC Provider and copying the
authentication response URL. This is an example of what it looks like:

```
  HTTP/1.1 302 Found
  Location: https://client.example.org/cb?
    code=SplxlOBeZQQYbYS6WxSbIA
```

We can protect against this attack by following the OIDC spec and using the
`state` parameter. This is how it works:

1. In the authentication request, the OIDC Client (AuthService) generates a
   secret state value. The OIDC Client sets a cookie with that value and also
   includes it in the URL parameters of the redirect to the OIDC Provider. This
   is what it looks like:

    ```
    HTTP/1.1 302 Found
    Location: https://server.example.com/authorize?
      response_type=code
      &scope=openid%20profile%20email
      &client_id=s6BhdRkqt3
      &state=<secret_value>
      &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
    Set-Cookie: oidc_state_csrf=<secret_value>
    ```

2. In the authentication response, the OIDC Provider includes the state value,
   given to it by the authentication request, in the URL parameters of the
   redirect:

    ```
    HTTP/1.1 302 Found
    Location: https://client.example.org/cb?
      code=SplxlOBeZQQYbYS6WxSbIA
      &state=<secret_value>
    ``` 

3. Finally, after receiving the authentication response, the client checks that
   the value in the URL parameter of the authentication response matches the
   value included inside the cookie we set in the first step.

Notice the attack no longer works, because the victim's browser doesn't have
the cookie set, as the first part of the OIDC flow (authentication request) was
performed in the attacker's browser.


## Logout CSRF

Logout CSRF occurs when an attacker logs out a user by making them visit a
specially crafted page. To protect against this kind of CSRF, we need to embed
some secret CSRF token in our logout form. However, the AuthService doesn't
render the HTML, so it can't do the job of injecting HTML forms with tokens and
then verifying them.

The alternative is to authenticate with a non-standard header (like
`Authorization`), so that the browser cannot be used to access the logout
endpoint. This is what we use in the AuthService. The UI must use javascript
to get the value of the session cookie and create an authenticated request to
the logout endpoint.
