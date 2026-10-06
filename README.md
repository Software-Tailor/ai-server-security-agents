# AI Server security agents

Security-operations agents that run on **your own hardware**, using
**[Software Tailor AI Server](https://softwaretailor.com/docs/ai-server/)** as the private model
behind them. Alerts, logs and verdicts never leave your network unless a tool you write sends them.

The starting point is a **SOC triage agent**: given an alert, it looks up the source's reputation, pulls the
host's recent events, decides whether to open a ticket, and returns a verdict. It is a plain OpenAI
tool-calling loop, so it works unchanged against any OpenAI-compatible server. Here it points at AI Server.

| Stack | File | Needs |
| --- | --- | --- |
| Python | [`python/triage_agent.py`](python/triage_agent.py) | `pip install -r python/requirements.txt` (the `openai` SDK) |
| C# / .NET | [`dotnet/Program.cs`](dotnet/Program.cs) | .NET 8 SDK (the `OpenAI` NuGet package) |
| PowerShell | [`scripts/smoke-test.ps1`](scripts/smoke-test.ps1) | PowerShell 7: checks the server before you point agents at it |

Both agents ship with **stub tools** (threat intel, SIEM query, ticketing) and two sample alerts, so you can
run them straight away and then swap in real integrations: Sentinel, Splunk, Wazuh, Elastic, MISP, OpenCTI,
ServiceNow, Jira and so on. The tool signatures are the seam.

## Run it

1. **AI Server running.** Install it from the Microsoft Store (or run the Docker image), start the server, and
   install a **tool-capable model** (see [Choosing a model](#choosing-a-model)).
2. **An API key.** Go to AI Server → **API keys** → *Add key*. If your agents run on other machines, the
   server needs *Access: This network*, which is a Pro feature.
3. Configure and run:

```bash
export AISERVER_BASE_URL="http://192.168.1.42:11436/v1"   # from AI Server's Server page — ends in /v1
export AISERVER_API_KEY="ai-suite_..."
export AISERVER_MODEL="enginea/qwen3/8b"                  # any id from GET /v1/models

pwsh scripts/smoke-test.ps1                               # optional: fail-fast connectivity check

cd python && pip install -r requirements.txt && python triage_agent.py ../samples/alert-rdp-bruteforce.json
cd dotnet && dotnet run -- ../samples/alert-rdp-bruteforce.json
```

Typical output for the brute-force sample:

```
  -> lookup_ip_reputation({'ip': '203.0.113.7'})
  -> get_host_events({'host': 'HOST-22', 'minutes': 30})
  -> open_ticket({'severity': 'high', 'summary': 'RDP brute force succeeded with new account creation', ...})
VERDICT: incident
```

`samples/alert-benign-vpn.json` should come back **benign**, which shows the agent doesn't escalate everything.

## Choosing a model

The model matters more than anything else in an agent. From testing these samples:

- **Use a general instruct model of 7–8B or larger** that supports tool calling: Qwen 3 / Qwen 2.5 instruct,
  Llama 3.1 8B instruct, or gpt-oss 20B on a GPU node. These return properly structured `tool_calls`.
- **Avoid code-tuned variants** (for example Qwen 2.5 *Coder*) for tool calling. They tend to write the call
  as JSON text in the message instead of a structured `tool_calls` entry, so no tool runs, and the model then
  invents a verdict.
- **Very small models (≈3B)** do call tools, but they repeat calls and give inconsistent verdicts across
  multi-step triage.
- **Always cap the loop** (`MAX_STEPS` here), and tell the model when it repeats a call rather than
  re-running it. Both samples do this.
- Use `tool_choice: "required"` for a step that *must* call a tool.

## Scaling out

Several analysts or agents can share one server, each with its own API key, rate limit and quota (the
limits and quotas are AI Server governance features). For more throughput or redundancy, run AI Server in
**gateway mode** in front of several worker servers: agents keep one endpoint, and every response carries
`X-AISuite-Backend` naming the server that answered. Every running server or gateway node is one licence.
See the [deployment docs](https://softwaretailor.com/docs/ai-server/install/kubernetes).

## Responsible use

These samples triage alerts; they do not attack anything. If you extend them with active tooling (scanning,
exploitation, account actions), use it **only on systems you own or are explicitly authorised in writing to
test**, and keep a human in the loop for anything destructive.

## More

- [AI Server API & clients](https://softwaretailor.com/docs/ai-server/api/): endpoints, streaming, tool calling, errors
- [Developer hub](https://softwaretailor.com/developers.htm): all samples and drop-in recipes
- [Partner Programme](https://softwaretailor.com/partners/): building a security product on AI Server? Technology partners get evaluation licences.

MIT licensed. See [LICENSE](LICENSE).
