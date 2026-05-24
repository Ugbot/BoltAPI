# run_benchmarks.ps1 — Windows-primary benchmark orchestration.
#
# Builds the benchmark targets (BOLTAPI_BUILD_BENCHMARKS=ON), starts the
# TechEmpower-style bench server, drives the in-tree async load generator against
# each endpoint, scrapes the RESULT line, and prints a table. The bench server is
# ALWAYS stopped in the finally block — no orphan process, no hang.
#
#   pwsh -File scripts\run_benchmarks.ps1 [-Duration 10] [-Connections 64]
#                                         [-Port 18080] [-BuildDir build/bench]
#                                         [-IoThreads 1] [-Workers 0] [-SkipBuild]
[CmdletBinding()]
param(
    [int]$Duration    = 10,
    [int]$Connections = 64,
    [int]$Port        = 18080,
    [string]$BuildDir = "build/bench",
    [int]$IoThreads   = 1,
    [int]$Workers     = 0,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

if (-not $SkipBuild) {
    Write-Host "==> Configuring + building benchmarks ($BuildDir)" -ForegroundColor Cyan
    cmake -S . -B $BuildDir -DBOLTAPI_BUILD_BENCHMARKS=ON | Out-Host
    cmake --build $BuildDir --config Release `
        --target boltapi_bench_server boltapi_loadgen | Out-Host
}

$serverExe  = Join-Path $repo "$BuildDir/benchmarks/Release/boltapi_bench_server.exe"
$loadgenExe = Join-Path $repo "$BuildDir/benchmarks/Release/boltapi_loadgen.exe"
foreach ($exe in @($serverExe, $loadgenExe)) {
    if (-not (Test-Path $exe)) { throw "missing benchmark exe: $exe (build first?)" }
}

# Endpoints to drive. Keep in sync with bench_server.cpp routes.
$endpoints = @("/plaintext", "/json", "/db", "/queries?n=20", "/route/42")

Write-Host "==> Starting bench server on 127.0.0.1:$Port" -ForegroundColor Cyan
$server = Start-Process -FilePath $serverExe `
    -ArgumentList @("$Port", "--io-threads", "$IoThreads", "--workers", "$Workers") `
    -PassThru -WindowStyle Hidden

$rows = @()
try {
    Start-Sleep -Milliseconds 700   # warmup

    foreach ($ep in $endpoints) {
        Write-Host "==> loadgen $ep" -ForegroundColor DarkGray
        $out = & $loadgenExe --host 127.0.0.1 --port $Port --path $ep `
            --connections $Connections --duration $Duration `
            --io-threads $IoThreads --workers $Workers 2>&1
        $line = ($out | Select-String -Pattern '^RESULT ').ToString()
        if (-not $line) {
            Write-Warning "no RESULT line for $ep"; continue
        }
        # Parse "key=value" tokens.
        $kv = @{}
        foreach ($tok in ($line -replace '^RESULT\s+', '').Split(' ')) {
            $p = $tok.Split('=', 2)
            if ($p.Count -eq 2) { $kv[$p[0]] = $p[1] }
        }
        $rows += [pscustomobject]@{
            endpoint = $ep
            'req/s'  = [double]$kv['rps']
            'MiB/s'  = [math]::Round([double]$kv['bytes_per_s'] / 1MB, 2)
            'p50_us' = [double]$kv['p50_us']
            'p90_us' = [double]$kv['p90_us']
            'p99_us' = [double]$kv['p99_us']
            'p999_us'= [double]$kv['p999_us']
            errors   = [int64]$kv['failed']
        }
    }
}
finally {
    if ($server -and -not $server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "== BoltAPI benchmark results (conns=$Connections, dur=${Duration}s) ==" -ForegroundColor Green
$rows | Format-Table -AutoSize
