#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    throw 'Windows contract tests require Windows. No system changes were made.'
}

Import-Module NetSecurity -ErrorAction Stop
Import-Module DnsClient -ErrorAction Stop
Import-Module Pester -MinimumVersion 6.0.0 -DisableNameChecking -ErrorAction Stop

Write-Host ''
Write-Host 'NETRULES WINDOWS CONTRACT TESTS (READ ONLY)' -ForegroundColor Cyan
Write-Host '[READ ONLY] Inspect installed NetSecurity and DnsClient cmdlet parameter metadata.'
Write-Host '[READ ONLY] Read PersistentStore Firewall rules and the seven associated filter collections.'
Write-Host '[READ ONLY] Read Firewall Profiles, local NRPT rules, and Dynamic Keyword Addresses.'
Write-Host '[READ ONLY] Compare native Windows objects with PSCustomObject fixtures through the same NetRules projection functions.'
Write-Host 'No Windows network settings are created, updated, or deleted.' -ForegroundColor Green
Write-Host ''

$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'PSNetRules.Windows.Contract.Tests.ps1'
$config.Run.Exit = $true
$config.Should.DisableV5 = $true
$config.Output.Verbosity = 'Detailed'

Invoke-Pester -Configuration $config
