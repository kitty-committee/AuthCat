# AuthCat

This project technically contains two sub-projects, a server application, and a client library.

## AuthCat Server application

This application serves as an AuthCat OAuth 2.0 ([RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749))
authorisation server. This application is part of my attempt to re-imagine [nathcat.net](https://nathcat.net) with a brand-new, modernised tech stack.

### Building

```
cmake -B build -DCLIENTBUILD=off
cmake --build build
```

### OAuth API Structure

#### Authorisation endpoint - `GET /auth`

Applications should direct users to this endpoint. Here the user will be prompted to login with their
AuthCat account.

For example:

```
GET /auth?response_type=code&client_id=<client_id>
```

If any part of the above request is incorrect:

- Invalid `<client_id>`
- `response_type != "code"`
- Invalid redirection URI

The server will NOT perform any further redirection, and will inform the user of the error.
Otherwise, the user will be prompted to login, upon success, the server will perform the following
redirection.

```
HTTP 302
GET <registered_client_redirection_url>?code=<authorization_grant_code>
```

Note that `<authorization_grant_code>` is _not_ an access token! It provides authorization
to _gain_ an access token.

If the user denies the request, the following redirection is performed:

```
HTTP 302
GET <registered_client_redirection_url>?error=<error>
```

#### Token endpoint - `POST /token`

This endpoint is used to obtain an access token using an authorization grant code:

```
POST /token
Authorization: Basic <client_id>
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<authorization_grant_code>
```

If the server successfully validates the request, its response will supply an access token:

```
HTTP 200
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{
  "access_token": <access_token>,
  "token_type": <token_type>
  "expires_in": 86400
}
```

If the server fails to validate the request, it will respond with an error response of the same format as the authorisation endpoint.

See [RFC 6749#7.1](https://datatracker.ietf.org/doc/html/rfc6749#section-7.1) for a description of
the `token_type` field. At the time of writing the server is planned to only utilise the `Bearer`
type (defined in [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750)).

## AuthCat Client library

This is a static library target designed to allow client applications to interact
with AuthCat more easily.

### Building

```
cmake -B build -DCLIENTBUILD=on
cmake --build build
```

Note that when including `AuthCat/auth.hpp`, one must define `AUTHCAT_CLIENT_MODE` beforehand, e.g.

```cpp
#define AUTHCAT_CLIENT_MODE
#include <AuthCat/auth.hpp
```

