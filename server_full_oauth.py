"""
The upgrade from the previous demo: this server IS a real OAuth 2.1
Authorization Server, not just a Resource Server. That means it has the
three things a browser-based client (like Claude) actually needs:

  GET  /authorize    -> shows a login page, then redirects back with a code
  POST /token        -> exchanges that code (or a refresh token) for a JWT
  POST /register     -> lets a client (Claude) register itself automatically

Everything else — token verification, scopes, the sample data tool — is the
same idea as before.

Run:
    pip install "mcp<2" pyjwt

Then, in another terminal:
    python client.py            # simulates a browser-based login + tool calls

Or attach it to Claude for real:
    Add a custom connector pointing at http://127.0.0.1:8000/mcp
    Claude will discover everything below automatically and pop up the
    login page in your browser.
"""

import secrets
import time
import uuid
from dataclasses import dataclass, field

import jwt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
)
from mcp.server.auth.provider import construct_redirect_uri
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)
from mcp.server.fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

SERVER_URL = "http://127.0.0.1:8000"
JWT_SECRET = "dev-secret-change-me-32-bytes-minimum"
ACCESS_TOKEN_TTL = 3600
REFRESH_TOKEN_TTL = 30 * 24 * 3600
AUTH_CODE_TTL = 300

# Pretend user directory. In real life: a database + hashed passwords.
USERS = {
    "alice": {"password": "alice-pw", "scopes": ["data:read"]},
    "bob": {"password": "bob-pw", "scopes": ["data:read", "data:write"]},
}
ALL_SCOPES = ["data:read", "data:write"]


# ---------------------------------------------------------------------------
# The Authorization Server itself
#
# This class is the whole story. It answers five questions the SDK asks it:
#   - who is this client, and can it register itself?           (get_client / register_client)
#   - the browser landed on /authorize — what should it see?     (authorize)
#   - the client is trading a code for tokens — mint them        (exchange_authorization_code)
#   - the client wants to refresh — mint new ones                (exchange_refresh_token)
#   - is this access token still good?                           (load_access_token)
# ---------------------------------------------------------------------------


@dataclass
class PendingLogin:
    client: OAuthClientInformationFull
    params: AuthorizationParams


class SimpleAuthProvider(OAuthAuthorizationServerProvider):
    def __init__(self) -> None:
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.pending_logins: dict[str, PendingLogin] = {}

    # -- dynamic client registration (RFC 7591) ----------------------------
    # Claude doesn't know our client_id ahead of time — it registers itself
    # the first time it connects, and we hand back an id it reuses after that.

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info

    # -- step 1: GET /authorize ---------------------------------------------
    # The SDK has already validated client_id, redirect_uri and scope by the
    # time this is called. We just need to decide what the browser sees next.
    # We show our own login page instead of redirecting to a 3rd-party IdP.

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        login_id = secrets.token_urlsafe(16)
        self.pending_logins[login_id] = PendingLogin(client=client, params=params)
        return f"{SERVER_URL}/login?login_id={login_id}"

    # -- step 2: the login page (not part of the OAuth spec — our own UI) --

    async def render_login_page(self, login_id: str) -> str:
        if login_id not in self.pending_logins:
            return "<h1>This login link expired. Go back and try connecting again.</h1>"
        return f"""
        <html><body style="font-family: sans-serif; max-width: 320px; margin: 80px auto;">
          <h2>Sign in</h2>
          <p>An app wants to access your data.</p>
          <form method="post" action="/login">
            <input type="hidden" name="login_id" value="{login_id}">
            <p><input name="username" placeholder="username" autofocus></p>
            <p><input name="password" type="password" placeholder="password"></p>
            <button type="submit">Sign in</button>
          </form>
          <p style="color:#888">Try alice/alice-pw or bob/bob-pw</p>
        </body></html>
        """

    # -- step 3: the login page is submitted --------------------------------
    # On success we mint an authorization code and send the browser back to
    # the client's redirect_uri — the standard end of the /authorize dance.

    async def handle_login_submit(self, login_id: str, username: str, password: str) -> str:
        pending = self.pending_logins.pop(login_id, None)
        if pending is None:
            raise AuthorizeError(error="access_denied", error_description="Login session expired")

        user = USERS.get(username)
        if not user or user["password"] != password:
            raise AuthorizeError(error="access_denied", error_description="Wrong username or password")

        # Only grant scopes the user actually has, intersected with what was requested.
        requested = pending.params.scopes or ALL_SCOPES
        granted = [s for s in requested if s in user["scopes"]]

        code = secrets.token_urlsafe(32)
        self.auth_codes[code] = AuthorizationCode(
            code=code,
            scopes=granted,
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=pending.client.client_id,
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=pending.params.resource,
            subject=username,  # <- who logged in; carried through to the final token
        )
        return construct_redirect_uri(
            str(pending.params.redirect_uri), code=code, state=pending.params.state
        )

    # -- step 4: POST /token with grant_type=authorization_code -------------
    # PKCE verification already happened inside the SDK before this is called.

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.auth_codes.get(authorization_code)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        del self.auth_codes[authorization_code.code]  # one-time use
        return self._issue_tokens(
            client_id=client.client_id,
            subject=authorization_code.subject or "unknown",
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
        )

    # -- refreshing, once the access token expires ---------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return self.refresh_tokens.get(refresh_token)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        del self.refresh_tokens[refresh_token.token]  # rotate: old one dies here
        return self._issue_tokens(
            client_id=client.client_id,
            subject=refresh_token.subject or "unknown",
            scopes=scopes or refresh_token.scopes,
            resource=refresh_token.resource,
        )

    def _issue_tokens(self, *, client_id: str, subject: str, scopes: list[str], resource: str | None) -> OAuthToken:
        now = int(time.time())
        access_token = jwt.encode(
            {
                "sub": subject,
                "aud": resource or SERVER_URL,
                "scope": " ".join(scopes),
                "client_id": client_id,
                "iat": now,
                "exp": now + ACCESS_TOKEN_TTL,
                "jti": uuid.uuid4().hex,
            },
            JWT_SECRET,
            algorithm="HS256",
        )
        refresh_token = secrets.token_urlsafe(32)
        self.refresh_tokens[refresh_token] = RefreshToken(
            token=refresh_token, client_id=client_id, scopes=scopes,
            expires_at=now + REFRESH_TOKEN_TTL, resource=resource, subject=subject,
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(scopes),
            refresh_token=refresh_token,
        )

    # -- step 5: verifying an access token on every MCP request -------------
    # Access tokens are plain JWTs, so verifying one is just decoding it —
    # no lookup needed. (Trade-off: see the note in the README about revocation.)

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            claims = jwt.decode(
                token, JWT_SECRET, algorithms=["HS256"],
                audience=SERVER_URL, options={"require": ["exp", "aud", "sub"]},
            )
        except jwt.PyJWTError:
            return None
        return AccessToken(
            token=token, client_id=claims.get("client_id", claims["sub"]),
            scopes=claims.get("scope", "").split(), expires_at=claims["exp"],
            resource=claims.get("aud"), subject=claims["sub"],
        )

    async def revoke_token(self, token) -> None:
        self.refresh_tokens.pop(getattr(token, "token", token), None)
        # Access tokens are stateless JWTs, so they remain valid until they
        # expire naturally — that's why ACCESS_TOKEN_TTL is short (1 hour)
        # and real revocation happens by killing the refresh token above.


provider = SimpleAuthProvider()


# ---------------------------------------------------------------------------
# The MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="sample-data-server",
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(SERVER_URL),
        resource_server_url=AnyHttpUrl(SERVER_URL),
        required_scopes=["data:read"],
        validate_token_resource=True,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=ALL_SCOPES, default_scopes=["data:read"],
        ),
        revocation_options=RevocationOptions(enabled=True),
    ),
)


@mcp.tool()
def get_sample_data(topic: str = "general") -> dict:
    """Return some sample JSON data. Stands in for a real data source."""
    catalog = {
        "general": [{"id": 1, "name": "Widget"}, {"id": 2, "name": "Gadget"}],
        "weather": [{"city": "Delhi", "temp_c": 34}, {"city": "Oslo", "temp_c": 12}],
    }
    return {"topic": topic, "rows": catalog.get(topic, catalog["general"])}


@mcp.tool()
def add_sample_row(name: str) -> dict:
    """A pretend 'write' action — needs the data:write scope, checked here
    because the session-level check above only guarantees data:read."""
    from mcp.server.auth.middleware.auth_context import get_access_token

    token = get_access_token()
    if token is None or "data:write" not in token.scopes:
        raise PermissionError("This action needs the 'data:write' scope.")
    return {"added": name, "by": token.subject}


# ---------------------------------------------------------------------------
# Wire it together
#
# mcp.streamable_http_app() already builds a Starlette app containing:
#   /mcp                                  the MCP endpoint itself
#   /authorize, /token, /register, /revoke   (because auth_server_provider is set)
#   /.well-known/oauth-authorization-server  (ditto)
#   /.well-known/oauth-protected-resource    (because token_verifier is set)
# We just add our own two routes for the login page on top.
# ---------------------------------------------------------------------------

base_app: Starlette = mcp.streamable_http_app()


async def login_page(request: Request):
    login_id = request.query_params.get("login_id", "")
    return HTMLResponse(await provider.render_login_page(login_id))


async def login_submit(request: Request):
    form = await request.form()
    try:
        redirect_url = await provider.handle_login_submit(
            form["login_id"], form["username"], form["password"]
        )
    except AuthorizeError as exc:
        return HTMLResponse(f"<h1>Login failed</h1><p>{exc.error_description}</p>", status_code=400)
    return RedirectResponse(url=redirect_url, status_code=302)


base_app.router.routes.insert(0, Route("/login", login_page, methods=["GET"]))
base_app.router.routes.insert(0, Route("/login", login_submit, methods=["POST"]))

app = base_app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
