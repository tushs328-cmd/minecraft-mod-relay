# Minecraft mod relay

Dependency-free WebSocket relay for the two-client Minecraft check session.

Deploy as a Render Web Service on the Free plan. Render provides the PORT
variable and terminates TLS, so Minecraft clients use:

    -Dmod.relay.uri=wss://<your-service>.onrender.com

The relay forwards the session protocol fields between clients sharing a
channel. It has no authentication; use a long random channel for private tests.
