# Smoke test from each client node (PowerShell 7). Checks reachability, auth, model list, one chat,
# and — behind a gateway — which worker answered (X-AISuite-Backend). Stops at the first failure with a diagnosis.
param(
  [string] $BaseUrl = ($env:AISERVER_BASE_URL -replace "/v1/?$", ""),   # e.g. http://192.168.1.42:11436 (no /v1)
  [string] $ApiKey = $env:AISERVER_API_KEY,
  [string] $Model = $env:AISERVER_MODEL           # optional; defaults to the first local (non cloud-*) model
)
$h = @{ Authorization = "Bearer $ApiKey" }

function Fail($msg) { Write-Host "FAIL  $msg" -ForegroundColor Red; exit 1 }
function Explain($r, $step) {
  $why = switch ($r.StatusCode) {
    401     { 'API key missing or wrong: issue one on the server''s API keys page.' }
    403     { 'Key valid but not allowed this model or route: check the key''s plan or governance policy.' }
    429     { if ($r.Headers['X-AISuite-Upgrade']) { 'Free-tier meter hit: the server is not licensed (network and API use need Pro).' }
              else { 'Rate limit or quota on this key: see the server''s governance settings.' } }
    503     { "All workers busy or down: retry after $($r.Headers['Retry-After']) s and check /dashboard." }
    default { "HTTP $($r.StatusCode): $($r.Content)" }
  }
  Fail "$step -> $why"
}

try { $r = Invoke-WebRequest "$BaseUrl/readyz" -SkipHttpErrorCheck -TimeoutSec 10 }
catch { Fail "readyz -> cannot reach $BaseUrl ($($_.Exception.Message)). Check the server's Access setting (This network), the port, and the firewall (Server page -> Network diagnostics)." }
if ($r.StatusCode -ne 200) { Explain $r 'readyz' }
Write-Host "OK    readyz"

$r = Invoke-WebRequest "$BaseUrl/v1/models" -Headers $h -SkipHttpErrorCheck -TimeoutSec 30
if ($r.StatusCode -ne 200) { Explain $r 'models' }
$ids = @(($r.Content | ConvertFrom-Json).data.id)
Write-Host "OK    models ($($ids.Count))"
if (-not $Model) { $Model = $ids | Where-Object { $_ -notlike 'cloud-*' } | Select-Object -First 1 }
if (-not $Model) { Fail 'no local model installed: install one on the server''s Models page, or pass -Model.' }

$body = @{ model = $Model; messages = @(@{ role = 'user'; content = 'Reply with the single word: pong' }) } | ConvertTo-Json -Depth 5
$r = Invoke-WebRequest "$BaseUrl/v1/chat/completions" -Method Post -Headers $h -ContentType 'application/json' -Body $body -SkipHttpErrorCheck -TimeoutSec 300
if ($r.StatusCode -ne 200) { Explain $r 'chat' }
$reply = ($r.Content | ConvertFrom-Json).choices[0].message.content
$backend = $r.Headers['X-AISuite-Backend']
if (-not $backend) { $backend = '(direct, no gateway)' }
Write-Host "OK    chat  model=$Model  backend=$backend  reply=$reply" -ForegroundColor Green
