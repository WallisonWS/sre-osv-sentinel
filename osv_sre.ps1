<#
.SYNOPSIS
    SRE & OSV Sentinel for Windows PowerShell — Queries Google OSV.dev API in real time!
.EXAMPLE
    .\osv_sre.ps1 -Ecosystem npm -Package lodash -Version 4.17.19
#>
param(
    [ValidateSet("npm", "PyPI", "Go", "Pub")]
    [string]$Ecosystem = "npm",
    [string]$Package = "lodash",
    [string]$Version = "4.17.19"
)

$body = @{
    version = $Version
    package = @{ name = $Package; ecosystem = $Ecosystem }
} | ConvertTo-Json -Depth 4

$resp = Invoke-RestMethod -Uri "https://api.osv.dev/v1/query" -Method Post -ContentType "application/json" -Body $body
$vulns = @($resp.vulns | ForEach-Object { [ordered]@{ id = $_.id; summary = $_.summary } })
[ordered]@{
    source      = "Google OSV.dev API (https://api.osv.dev)"
    ecosystem   = $Ecosystem
    package     = $Package
    version     = $Version
    vuln_count  = $vulns.Count
    vulns       = $vulns
} | ConvertTo-Json -Depth 5
