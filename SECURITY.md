# Security policy

These are **sample agents**. They hold no secrets of their own: your AI Server base URL and API key
come from environment variables at run time and are never written to the repository.

## Reporting a vulnerability

Please report security issues in AI Server itself, or in these samples, **privately** to
**support@softwaretailor.com** — not through public GitHub issues.

Include what you did, what happened, and the AI Server version (Settings → About). We'll acknowledge
your report and keep you updated on the fix.

## Handling keys safely

- Treat an AI Server API key like a password: it grants use of that server's models.
- Keep keys in environment variables or a secret store — never in source, screenshots, or issues.
- Revoke a key in **AI Server → API keys** the moment it may have been exposed. Revocation is immediate;
  the server does not need restarting.
- Serving a network exposes the API to every device that can reach the port. Serve only networks you
  trust, and prefer marking that network **Private** in Windows over opening the port on a public one.
