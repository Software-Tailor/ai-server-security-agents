// SOC triage agent on your own hardware — the same tool-calling loop as python/triage_agent.py, in C#
// with the official OpenAI .NET library pointed at Software Tailor AI Server.
//
//   set AISERVER_BASE_URL / AISERVER_API_KEY / AISERVER_MODEL (see README), then:
//   dotnet run -- ../samples/alert-rdp-bruteforce.json
//
// The three tools are stubs with clear seams: replace them with your SIEM, threat-intel and ticketing.
using System.ClientModel;
using System.Text.Json;
using OpenAI;
using OpenAI.Chat;

const int MaxSteps = 8; // always cap an agent loop

var baseUrl = Environment.GetEnvironmentVariable("AISERVER_BASE_URL") ?? throw new InvalidOperationException("Set AISERVER_BASE_URL (ends in /v1).");
var apiKey = Environment.GetEnvironmentVariable("AISERVER_API_KEY") is { Length: > 0 } k ? k : "none";
var model = Environment.GetEnvironmentVariable("AISERVER_MODEL") ?? throw new InvalidOperationException("Set AISERVER_MODEL to a tool-capable model id.");

var client = new ChatClient(model, new ApiKeyCredential(apiKey), new OpenAIClientOptions { Endpoint = new Uri(baseUrl) });

var alertPath = args.Length > 0 ? args[0] : Path.Combine("..", "samples", "alert-rdp-bruteforce.json");
var alert = File.ReadAllText(alertPath);

ChatTool Tool(string name, string description, string schema) =>
    ChatTool.CreateFunctionTool(name, description, BinaryData.FromString(schema));

var options = new ChatCompletionOptions
{
    Tools =
    {
        Tool("lookup_ip_reputation", "Threat-intel reputation for an IP address.",
             """{ "type": "object", "properties": { "ip": { "type": "string" } }, "required": ["ip"] }"""),
        Tool("get_host_events", "Recent security events for a host from the SIEM.",
             """{ "type": "object", "properties": { "host": { "type": "string" }, "minutes": { "type": "integer" } }, "required": ["host"] }"""),
        Tool("open_ticket", "Open a SOC ticket. Call only when the evidence supports an incident.",
             """{ "type": "object", "properties": { "severity": { "type": "string", "enum": ["low","medium","high","critical"] }, "summary": { "type": "string" }, "evidence": { "type": "string" } }, "required": ["severity","summary","evidence"] }"""),
    },
    ToolChoice = ChatToolChoice.CreateAutoChoice(),
};

List<ChatMessage> messages =
[
    new SystemChatMessage("You are a SOC triage analyst. Investigate the alert with the tools before concluding: check the source " +
                          "reputation and the host's recent events. Open a ticket only if the evidence shows an incident. " +
                          "Finish with one line 'VERDICT: benign|suspicious|incident' followed by a short justification."),
    new UserChatMessage("Alert:\n" + alert),
];

var seen = new HashSet<string>();
for (var step = 0; step < MaxSteps; step++)
{
    ChatCompletion completion = await client.CompleteChatAsync(messages, options);
    if (completion.ToolCalls.Count == 0)
    {
        Console.WriteLine(completion.Content.Count > 0 ? completion.Content[0].Text : "");
        return;
    }

    messages.Add(new AssistantChatMessage(completion));
    foreach (var call in completion.ToolCalls)
    {
        var callArgs = call.FunctionArguments.ToString();
        string result = seen.Add(call.FunctionName + callArgs)
            ? Dispatch(call.FunctionName, callArgs)
            : """{"note":"already called with these arguments; use the earlier result"}""";
        Console.Error.WriteLine($"  -> {call.FunctionName}({callArgs})");
        messages.Add(new ToolChatMessage(call.Id, result));
    }
}
Console.WriteLine("VERDICT: suspicious — stopped at the step limit; review manually.");

// ── Tools (stubs) — replace the bodies, keep the signatures ──────────────────────────────────────────
static string Dispatch(string name, string json)
{
    using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json);
    var a = doc.RootElement;
    string Arg(string key) => a.TryGetProperty(key, out var v) ? v.ToString() : "";
    object result = name switch
    {
        "lookup_ip_reputation" => Arg("ip") switch
        {
            "203.0.113.7" => new { ip = "203.0.113.7", reputation = "malicious", tags = new[] { "RDP brute force" }, score = 92 },
            "198.51.100.20" => new { ip = "198.51.100.20", reputation = "benign", tags = new[] { "corporate VPN egress" }, score = 0 },
            var ip => new { ip, reputation = "unknown", tags = Array.Empty<string>(), score = 0 },
        },
        "get_host_events" => Arg("host").ToUpperInvariant() switch
        {
            "HOST-22" => new
            {
                host = "HOST-22",
                events = new object[]
                {
                    new { id = 4625, count = 37, src = "203.0.113.7", desc = "failed logon (RDP)" },
                    new { id = 4624, count = 1, src = "203.0.113.7", desc = "successful logon type 10 (RDP)" },
                    new { id = 4720, count = 1, src = "local", desc = "user account created: svc_backup2" },
                },
            },
            var host => new { host, events = Array.Empty<object>() },
        },
        "open_ticket" => new { ticket = "SOC-1042", severity = Arg("severity"), summary = Arg("summary") },
        _ => new { error = $"unknown tool {name}" },
    };
    return JsonSerializer.Serialize(result);
}
