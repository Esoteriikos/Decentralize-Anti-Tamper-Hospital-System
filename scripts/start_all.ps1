# Launches the full local stack in four separate PowerShell windows.
# Useful for the demo recording: each window stays open and shows logs.

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $root

$python = "python"
$services = @(
  @{ name = "node_a";  cmd = "`$env:NODE_ID='node_a'; `$env:NODE_PORT='5311'; $python -m node_server" },
  @{ name = "node_b";  cmd = "`$env:NODE_ID='node_b'; `$env:NODE_PORT='5312'; $python -m node_server" },
  @{ name = "node_c";  cmd = "`$env:NODE_ID='node_c'; `$env:NODE_PORT='5313'; $python -m node_server" },
  @{ name = "gateway"; cmd = "$python -m gateway" }
)

foreach ($svc in $services) {
  $title = $svc.name
  $script = "Set-Location -Path '$root'; Write-Host '[$title] starting...' -ForegroundColor Cyan; $($svc.cmd)"
  Start-Process powershell -ArgumentList "-NoExit", "-Command", $script -WindowStyle Normal
  Start-Sleep -Milliseconds 600
}

Write-Host "All four services launched in separate PowerShell windows." -ForegroundColor Green
Write-Host "Web UI:    http://127.0.0.1:5310/" -ForegroundColor Green
Write-Host "Gateway API: http://127.0.0.1:5310/api" -ForegroundColor Green
