<#
.SYNOPSIS
Detect a Windows-host Ollama server and save its container-reachable URL in AIPAM.

.DESCRIPTION
Docker containers cannot inspect Windows processes or discover an arbitrary host
port. This bootstrap command finds the listening port owned by ``ollama.exe``,
verifies its /api/tags endpoint locally, then persists the corresponding
``host.docker.internal`` URL through AIPAM's authenticated runtime API.

.PARAMETER ApiBase
The AIPAM API base URL. Defaults to the local Docker deployment.

.PARAMETER ApiToken
An AIPAM bearer token. When omitted, the script reads AIPAM_API_TOKEN from the
repository .env file without printing it.
#>
[CmdletBinding()]
param(
    [string]$ApiBase = "http://localhost:8000/api/v1",
    [string]$ApiToken
)

$ErrorActionPreference = "Stop"

function Get-AipamToken {
    param([string]$ProvidedToken)
    if ($ProvidedToken) { return $ProvidedToken }

    $envFile = Join-Path (Split-Path -Parent $PSScriptRoot) ".env"
    if (-not (Test-Path -LiteralPath $envFile)) {
        throw "No API token was provided and $envFile does not exist. Pass -ApiToken."
    }
    $line = Get-Content -LiteralPath $envFile |
        Where-Object { $_ -match '^AIPAM_API_TOKEN=' } |
        Select-Object -First 1
    if (-not $line) {
        throw "AIPAM_API_TOKEN was not found in $envFile. Pass -ApiToken."
    }
    return $line.Substring("AIPAM_API_TOKEN=".Length)
}

$ollamaProcesses = @(Get-CimInstance Win32_Process -Filter "Name = 'ollama.exe'")
if ($ollamaProcesses.Count -eq 0) {
    throw "No running ollama.exe process was found. Start Ollama first."
}

$processIds = @($ollamaProcesses | Select-Object -ExpandProperty ProcessId)
$ports = @(Get-NetTCPConnection -State Listen |
    Where-Object { $processIds -contains $_.OwningProcess } |
    Select-Object -ExpandProperty LocalPort -Unique |
    Sort-Object)
if ($ports.Count -eq 0) {
    throw "Ollama is running but has no listening TCP port."
}

$detectedPort = $null
$models = @()
foreach ($port in $ports) {
    try {
        $probe = Invoke-RestMethod -UseBasicParsing -TimeoutSec 4 -Uri "http://127.0.0.1:$port/api/tags"
        if ($null -ne $probe.models) {
            $detectedPort = $port
            $models = @($probe.models)
            break
        }
    } catch {
        continue
    }
}
if ($null -eq $detectedPort) {
    throw "No listening ollama.exe port answered /api/tags."
}

$token = Get-AipamToken $ApiToken
$ollamaUrl = "http://host.docker.internal:$detectedPort"
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
$body = @{ ollama_url = $ollamaUrl } | ConvertTo-Json -Compress
$result = Invoke-RestMethod -Method Put -Uri "$($ApiBase.TrimEnd('/'))/embedding-model/runtime" -Headers $headers -Body $body

[PSCustomObject]@{
    ollama_url = $result.ollama_url
    detected_port = $detectedPort
    installed_models = $models.Count
    note = "The embedding-model selection was cleared because the Ollama endpoint changed."
}
