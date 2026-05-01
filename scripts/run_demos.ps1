# Run all the demo scripts in order against a running stack.
# Assumes the gateway is at http://127.0.0.1:5310 and the three nodes
# are at 5311 / 5312 / 5313 (the defaults).

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $root
Set-Location -Path $root

$demos = @(
  "demo.d00_bootstrap",
  "demo.d01_doctor_creates_audits",
  "demo.d02_patient_queries_own",
  "demo.d03_patient_queries_other",
  "demo.d04_audit_company_queries_all",
  "demo.d05_unauthorized_doctor",
  "demo.d07_verify",
  "demo.d06_tamper_node_b",
  "demo.d07_verify"
)

foreach ($d in $demos) {
  Write-Host ""
  Write-Host "==========================================================" -ForegroundColor Yellow
  Write-Host "  python -m $d" -ForegroundColor Yellow
  Write-Host "==========================================================" -ForegroundColor Yellow
  python -m $d
  if ($LASTEXITCODE -ne 0) {
    Write-Host "[run_demos] $d failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
  }
}

Write-Host ""
Write-Host "All demos completed." -ForegroundColor Green
