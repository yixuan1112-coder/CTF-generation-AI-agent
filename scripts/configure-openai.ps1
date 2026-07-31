param(
    [string]$Model = "gpt-5-mini",
    [switch]$StartStudio
)

$ErrorActionPreference = "Stop"

Write-Host "OpenAI API key setup for the local CTF Studio"
Write-Host "The key is entered privately and is never printed or written to the repository."

$secureKey = Read-Host "Paste your OpenAI API key" -AsSecureString
$keyPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)

try {
    $apiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($keyPointer)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($keyPointer)
}

if ([string]::IsNullOrWhiteSpace($apiKey) -or $apiKey.Length -lt 20 -or $apiKey -match "\s") {
    throw "The value does not look like a valid API key."
}

# Persist for future terminals and also expose it to child processes started by this script.
[Environment]::SetEnvironmentVariable("OPENAI_API_KEY", $apiKey, "User")
[Environment]::SetEnvironmentVariable("LLM_BASE_URL", "https://api.openai.com/v1", "User")
[Environment]::SetEnvironmentVariable("LLM_MODEL", $Model, "User")
$env:OPENAI_API_KEY = $apiKey
$env:LLM_BASE_URL = "https://api.openai.com/v1"
$env:LLM_MODEL = $Model

$apiKey = $null
$secureKey.Dispose()

Write-Host ""
Write-Host "Configured OPENAI_API_KEY for this Windows user."
Write-Host "Model: $Model"
Write-Host "Restart the CTF Studio so it can read the new environment."

if ($StartStudio) {
    python -m ctf_factory.cli studio
}
