# MCP server with real OAuth-style auth (sample data only)

No external system involved — just enough auth to see how it's actually
supposed to work, and a tool that returns sample JSON instead of hitting a
real backend.

## Run

    pip install "mcp<2" fastapi uvicorn pyjwt python-multipart httpx

    # terminal 1
    python server.py

    # terminal 2
    python client.py

`client.py` logs in as two different users (different scopes) and shows what
each one can and can't do, plus what happens with no token at all.
