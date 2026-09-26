"""
SOC triage agent on your own hardware — a tool-calling loop against Software Tailor AI Server.

  pip install -r requirements.txt
  export AISERVER_BASE_URL=http://192.168.1.42:11436/v1   # from AI Server's Server page
  export AISERVER_API_KEY=ai-suite_...                     # AI Server -> API keys
  export AISERVER_MODEL=enginea/qwen3/8b                   # a tool-capable model (see README)
  python triage_agent.py ../samples/alert-rdp-bruteforce.json

The loop runs in YOUR code; AI Server only decides which tool to call next. The three tools are stubs
with clear seams: replace them with calls to your SIEM, EDR, threat-intel and ticketing systems.
Nothing here leaves your network unless a tool you write sends it somewhere.
"""
import json
import os
import sys

from openai import OpenAI

MAX_STEPS = 8  # always cap an agent loop — small models can repeat a tool call forever

# max_retries: the SDK retries 429/503 honouring Retry-After (gateway backpressure, free-tier meter).
client = OpenAI(base_url=os.environ["AISERVER_BASE_URL"], api_key=os.environ.get("AISERVER_API_KEY") or "none",
                max_retries=5, timeout=300)


def pick_model() -> str:
    """Use AISERVER_MODEL, else the first local (non cloud-*) model the server reports."""
    if os.environ.get("AISERVER_MODEL"):
        return os.environ["AISERVER_MODEL"]
    ids = [m.id for m in client.models.list().data]
    local = [i for i in ids if not i.startswith("cloud-")]
    if not local:
        sys.exit("No local model installed — install a tool-capable model in AI Server -> Models, or set AISERVER_MODEL.")
    return local[0]


# ── Tools (stubs) — replace the bodies, keep the signatures ─────────────────────────────────────────

def lookup_ip_reputation(ip: str) -> dict:
    """Your threat-intel source (MISP, OpenCTI, a vendor feed…)."""
    known = {"203.0.113.7": ("malicious", ["RDP brute force", "credential stuffing"], 92),
             "198.51.100.20": ("benign", ["corporate VPN egress"], 0)}
    rep, tags, score = known.get(ip, ("unknown", [], 0))
    return {"ip": ip, "reputation": rep, "tags": tags, "score": score}


def get_host_events(host: str, minutes: int = 60) -> dict:
    """Your SIEM/EDR query (Sentinel, Splunk, Wazuh, Elastic…). Stub data keyed by host."""
    events = {
        "HOST-22": [
            {"id": 4625, "count": 37, "src": "203.0.113.7", "desc": "failed logon (RDP)"},
            {"id": 4624, "count": 1, "src": "203.0.113.7", "desc": "successful logon type 10 (RDP)"},
            {"id": 4720, "count": 1, "src": "local", "desc": "user account created: svc_backup2"},
        ],
        "LAPTOP-107": [
            {"id": 4624, "count": 1, "src": "198.51.100.20", "desc": "successful logon via corporate VPN, MFA satisfied"},
        ],
    }
    return {"host": host, "window_min": minutes, "events": events.get(host.upper(), [])}


def open_ticket(severity: str, summary: str, evidence: str) -> dict:
    """Your ticketing system (ServiceNow, Jira, ConnectWise, Autotask…)."""
    return {"ticket": "SOC-1042", "severity": severity, "summary": summary}


TOOLS_IMPL = {f.__name__: f for f in (lookup_ip_reputation, get_host_events, open_ticket)}
TOOLS = [
    {"type": "function", "function": {
        "name": "lookup_ip_reputation", "description": "Threat-intel reputation for an IP address.",
        "parameters": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}}},
    {"type": "function", "function": {
        "name": "get_host_events", "description": "Recent security events for a host from the SIEM.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string"}, "minutes": {"type": "integer", "description": "look-back window"}},
            "required": ["host"]}}},
    {"type": "function", "function": {
        "name": "open_ticket", "description": "Open a SOC ticket. Call only when the evidence supports an incident.",
        "parameters": {"type": "object", "properties": {
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "summary": {"type": "string"}, "evidence": {"type": "string"}},
            "required": ["severity", "summary", "evidence"]}}},
]

SYSTEM = (
    "You are a SOC triage analyst. Investigate the alert with the tools before concluding: check the source "
    "reputation and the host's recent events. Open a ticket only if the evidence shows an incident. "
    "Finish with one line 'VERDICT: benign|suspicious|incident' followed by a short justification."
)


def run(alert: dict, model: str) -> str:
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": "Alert:\n" + json.dumps(alert, indent=2)}]
    seen = set()
    for step in range(MAX_STEPS):
        r = client.chat.completions.create(model=model, messages=messages, tools=TOOLS, tool_choice="auto")
        msg = r.choices[0].message
        if not msg.tool_calls:
            return msg.content or ""
        messages.append(msg.model_dump(exclude_none=True))
        for call in msg.tool_calls:
            args = json.loads(call.function.arguments or "{}")
            key = (call.function.name, json.dumps(args, sort_keys=True))
            if key in seen:  # the same call again adds nothing — tell the model instead of re-running it
                result = {"note": "already called with these arguments; use the earlier result"}
            else:
                seen.add(key)
                fn = TOOLS_IMPL.get(call.function.name)
                result = fn(**args) if fn else {"error": f"unknown tool {call.function.name}"}
            print(f"  -> {call.function.name}({args})", file=sys.stderr)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
    return "VERDICT: suspicious — stopped at the step limit; review manually."


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "samples", "alert-rdp-bruteforce.json")
    with open(path, encoding="utf-8") as f:
        alert = json.load(f)
    model = pick_model()
    print(f"model: {model}", file=sys.stderr)
    print(run(alert, model))
