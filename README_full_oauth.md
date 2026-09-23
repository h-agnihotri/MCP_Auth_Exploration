# The full OAuth version (what Claude actually needs)

`server_full_oauth.py` is the previous demo upgraded so the server IS the
Authorization Server, not just a resource that trusts one. It exposes:

    GET  /authorize    (browser lands here, sees a login page)
    POST /login         (our own page — not part of the OAuth spec)
    POST /token         (authorization_code + refresh_token grants)
    POST /register      (dynamic client registration, RFC 7591)
    GET  /.well-known/oauth-authorization-server
    GET  /.well-known/oauth-protected-resource
    POST /mcp            (the actual MCP endpoint, bearer-protected)

This is the shape Claude's connector UI expects: point it at
`http://127.0.0.1:8000/mcp`, it registers itself, opens the login page in a
browser popup, and everything else happens automatically.

## Run

    pip install "mcp<2" pyjwt httpx
    python server_full_oauth.py

    # in another terminal — simulates exactly what Claude's OAuth client does
    python client_full_oauth.py

Login with `alice/alice-pw` (read-only) or `bob/bob-pw` (read+write) when
prompted, if trying the real browser flow by hand at
http://127.0.0.1:8000/authorize.

## What's still simplified

- Users are a hardcoded dict, not a real database with hashed passwords.
- The signing secret is a plain string (HS256). Swap for RS256 + a JWKS
  endpoint if multiple services need to verify tokens independently.
- Access tokens are stateless JWTs, so revoking one only takes effect at
  expiry (1 hour here) — revoking the refresh token stops renewal, but an
  already-issued access token stays valid until it naturally expires.
