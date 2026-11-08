#requires -Version 5.1
[CmdletBinding()]
param(
    [switch] $AllowSystemChanges
)

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Windows integration tests require Windows. No changes were made.'
}

Import-Module NetSecurity -ErrorAction Stop
Import-Module DnsClient -ErrorAction Stop
Import-Module Pester -MinimumVersion 6.0.0 -DisableNameChecking -ErrorAction Stop
$repositoryRoot = Split-Path -Parent $PSScriptRoot
Get-Module -Name PSNetRules | Remove-Module -Force -ErrorAction SilentlyContinue
$script:NetRulesModule = Import-Module (Join-Path $repositoryRoot 'src\PSNetRules.psm1') -Force -PassThru -ErrorAction Stop
Assert-NRAdministrator

# Give every temporary resource a run-specific identity so cleanup can target
# only resources created by this invocation.
$runId = [guid]::NewGuid().ToString('N')
$firewallName = "NetRulesIntegration-$runId-Firewall"
$nrptLogicalId = "netrules-integration-$runId"
$nrptNamespace = ".netrules-$runId.invalid"
$dynamicId = '{' + [guid]::NewGuid().ToString() + '}'
$dynamicKeyword = "netrules-$runId"

# Abort before running tests if any generated identity already exists. Never
# adopt or overwrite a resource that was not created by this run.
$firewallCollision = @(Get-NetFirewallRule -Name $firewallName -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
$nrptCollision = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { @($_.Namespace) -contains $nrptNamespace })
$dynamicCollision = @(Get-NetFirewallDynamicKeywordAddress -All -PolicyStore PersistentStore -ErrorAction Stop |
    Where-Object { [string]$_.Id -eq $dynamicId -or [string]$_.Keyword -eq $dynamicKeyword })
if ($firewallCollision.Count -gt 0 -or $nrptCollision.Count -gt 0 -or $dynamicCollision.Count -gt 0) {
    throw 'A generated integration-test identifier already exists. No resources were modified.'
}

Write-Host ''
Write-Host 'NETRULES WINDOWS INTEGRATION TEST PLAN' -ForegroundColor Cyan
Write-Host 'The following tests use real Windows cmdlets. No existing Firewall or NRPT entry is intentionally modified.' -ForegroundColor Yellow
Write-Host ''
Write-Host '[READ ONLY] Capture Firewall PersistentStore rules and all seven associated filter types.'
Write-Host '[READ ONLY] Read Firewall Profiles: Domain, Private, Public.'
Write-Host '[READ ONLY] Read local NRPT rules.'
Write-Host '[MOCK COMPATIBILITY] Compare the test-created NRPT and Dynamic Keyword Address native objects with PSCustomObject Unit fixtures through the same production projection functions.'
Write-Host ''
Write-Host '[CREATE] Firewall rule:'
Write-Host "  Name: $firewallName"
Write-Host '  Store: PersistentStore; Enabled: False; Profile: Private; Direction: Inbound; Action: Allow; Protocol: TCP; LocalPort: 54321'
Write-Host "[UPDATE] Same Firewall rule: DisplayName '$firewallName original' -> '$firewallName updated'; LocalPort 54321 -> 54322"
Write-Host "[DELETE] Same Firewall rule: Name '$firewallName' from PersistentStore"
Write-Host ''
Write-Host '[CREATE] Local NRPT rule:'
Write-Host "  Logical id: $nrptLogicalId"
Write-Host "  Namespace: $nrptNamespace"
Write-Host '  NameServers: 127.0.0.1'
Write-Host "[RECREATE] Same NRPT rule: NameServers 127.0.0.1 -> 127.0.0.2 (Windows-generated GUID will change)"
Write-Host "[DELETE] The NRPT rule created by this test, identified by the exact Namespace '$nrptNamespace'"
Write-Host ''
Write-Host '[CREATE] Static Dynamic Keyword Address:'
Write-Host "  Id: $dynamicId"
Write-Host "  Keyword: $dynamicKeyword"
Write-Host '  Addresses: 192.0.2.10'
Write-Host '[UPDATE] Same Dynamic Keyword Address: 192.0.2.10 -> 192.0.2.20'
Write-Host "[DELETE] Same Dynamic Keyword Address: Id '$dynamicId'"
Write-Host ''
Write-Host '[NO WRITE] Firewall Profiles are read only in this suite. Set-NetFirewallProfile is not called.' -ForegroundColor Green
Write-Host 'Cleanup is restricted to the exact random identifiers printed above. NRPT cleanup uses -Force to avoid an interactive deletion prompt.'
Write-Host ''

if (-not $AllowSystemChanges) {
    Write-Host 'PREVIEW ONLY: no system changes were made. Rerun with -AllowSystemChanges to authorize execution.' -ForegroundColor Yellow
    return
}

$confirmation = Read-Host "To authorize these local system changes, type 'RUN NETRULES INTEGRATION TESTS'"
if ($confirmation -cne 'RUN NETRULES INTEGRATION TESTS') {
    Write-Host 'Cancelled. No changes were made.' -ForegroundColor Yellow
    return
}

$environmentNames = @(
    'NETRULES_INTEGRATION_RUN_ID',
    'NETRULES_INTEGRATION_FIREWALL_NAME',
    'NETRULES_INTEGRATION_NRPT_ID',
    'NETRULES_INTEGRATION_NRPT_NAMESPACE',
    'NETRULES_INTEGRATION_DYNAMIC_ID',
    'NETRULES_INTEGRATION_DYNAMIC_KEYWORD'
)
$previousEnvironment = @{}
foreach ($name in $environmentNames) { $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

try {
    $env:NETRULES_INTEGRATION_RUN_ID = $runId
    $env:NETRULES_INTEGRATION_FIREWALL_NAME = $firewallName
    $env:NETRULES_INTEGRATION_NRPT_ID = $nrptLogicalId
    $env:NETRULES_INTEGRATION_NRPT_NAMESPACE = $nrptNamespace
    $env:NETRULES_INTEGRATION_DYNAMIC_ID = $dynamicId
    $env:NETRULES_INTEGRATION_DYNAMIC_KEYWORD = $dynamicKeyword

    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $repositoryRoot 'integration-tests\PSNetRules.Windows.Integration.Tests.ps1'
    $config.Should.DisableV5 = $true
    $config.Output.Verbosity = 'Detailed'
    $result = Invoke-Pester -Configuration $config
}
finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
}

if ($null -ne $result -and $result.FailedCount -gt 0) {
    exit 1
}
