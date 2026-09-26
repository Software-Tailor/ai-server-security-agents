# Contributing

Thanks for helping improve these samples.

## What belongs here

Security-operations agents that run against AI Server's OpenAI-compatible API and that a developer can read
in one sitting: triage, enrichment, summarisation, detection-rule drafting, report writing. A change earns its
place if it makes it easier to build a private security agent.

## Ground rules

- **No secrets, no real data.** No API keys, hostnames, IPs or logs from real environments. Sample alerts use
  documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`).
- **Defensive by default.** Active or offensive tooling must be clearly marked, off by default, and documented
  as "authorised targets only".
- **Run it before you send it.** Say in your PR which model you used and paste the agent's tool calls and verdict.
- **Cap every loop** and keep the stub-tool seam, so integrations stay swappable.
- Configuration comes from `AISERVER_BASE_URL` / `AISERVER_API_KEY` / `AISERVER_MODEL`.

## Licence

Contributions are accepted under the [MIT Licence](LICENSE).
