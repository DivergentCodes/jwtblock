# Local Example Using Docker Compose

This example starts a series of Docker containers, including a demo UI app and an instance of JWT Block. An Nginx proxy accepts all incoming web connections for the `*.localhost` network. For calls to the protected API, `api.localhost`, Nginx will forward requests to JWT Block to check if the request token is both valid not blocked.


## Quick Start

Build the current code into a local Docker image, and serve the containers
using Docker Compose. Use `CTRL-C` to shut the container down.

```
make start
```

Stop and clear all of the containers.

```
make stop
```

When the containers are up, browse to [http://ui-app.localhost](http://ui-app.localhost). There are a few controls:
- Login: redirects to the IdP (Keycloak). Login with `alice`:`password`.
- Call API: sends a GET request to http://api.localhost/json, which
    requires authentication. If the UI app has a token, it will be used.
- Logout: call JWT block, blocking the token from making future
    authenticated calls.
- Clear State: clears the tokens from the UI app.
