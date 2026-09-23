"""
Simulates exactly what Claude does when you attach this server as a custom
connector: register itself, send you to a login page in a "browser", get
redirected back with a code, trade it for tokens, then call MCP tools with
the access token — and refresh when it's about to expire.

Run this AFTER starting server_full_oauth.py in another terminal.
"""

import asyncio
import base64
import hashlib
import secrets
import webbrowser

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

BASE = "http://127.0.0.1:8000"
REDIRECT_URI = "http://localhost:9999/callback"  # Claude's own loopback listener, in real life


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


async def oauth_login(username: str, password: str) -> dict:
    """Everything Claude's OAuth client does automatically, spelled out."""
    async with httpx.AsyncClient() as http:
        # 1. Register once (Claude does this the first time you add the connector).
        client = (
            await http.post(
                f"{BASE}/register",
                json={
                    "redirect_uris": [REDIRECT_URI],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "token_endpoint_auth_method": "none",
                    "scope": "data:read data:write",
                },
            )
        ).json()
        client_id = client["client_id"]

        # 2. Build a PKCE challenge and open /authorize. In real life this is
        #    an actual browser window; here we just follow the redirects.
        verifier, challenge = pkce_pair()
        authorize = await http.get(
            f"{BASE}/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "demo-state",
                "scope": "data:read data:write",
            },
            follow_redirects=False,
        )
        login_url = authorize.headers["location"]  # -> our own /login page

        # 3. "You" see the login form and submit it.
        login_id = login_url.split("login_id=")[1]
        login_result = await http.post(
            f"{BASE}/login",
            data={"login_id": login_id, "username": username, "password": password},
            follow_redirects=False,
        )
        callback_url = login_result.headers["location"]
        code = callback_url.split("code=")[1].split("&")[0]

        # 4. Trade the code for tokens.
        tokens = (
            await http.post(
                f"{BASE}/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
            )
        ).json()
        return {**tokens, "client_id": client_id}


async def call_tools(access_token: str):
    headers = {"Authorization": f"Bearer {access_token}"}
    async with streamablehttp_client(f"{BASE}/mcp", headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            r = await session.call_tool("get_sample_data", {"topic": "weather"})
            print("  get_sample_data ->", r.content[0].text.replace("\n", " "))
            r = await session.call_tool("add_sample_row", {"name": "Sprocket"})
            text = r.content[0].text if not r.isError else f"DENIED: {r.content[0].text}"
            print("  add_sample_row ->", text)


async def main():
    print("--- alice (data:read only) ---")
    tokens = await oauth_login("alice", "alice-pw")
    print("  got scopes:", tokens["scope"])
    await call_tools(tokens["access_token"])

    print("\n--- bob (data:read + data:write) ---")
    tokens = await oauth_login("bob", "bob-pw")
    print("  got scopes:", tokens["scope"])
    await call_tools(tokens["access_token"])


if __name__ == "__main__":
    asyncio.run(main())
