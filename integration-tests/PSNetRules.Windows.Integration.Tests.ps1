BeforeAll {
    if ($env:OS -ne 'Windows_NT') {
        throw 'These integration tests run only on Windows.'
    }

    Import-Module NetSecurity -ErrorAction Stop
    Import-Module DnsClient -ErrorAction Stop
    $modulePath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\src\PSNetRules.psm1'))
    $loadedModules = @(Get-Module -Name PSNetRules | Where-Object { $_.Path -eq $modulePath })
    if ($loadedModules.Count -gt 1) { throw 'Multiple PSNetRules module instances are loaded.' }
    if ($loadedModules.Count -eq 1) { $script:NetRulesModule = $loadedModules[0] }
    else { $script:NetRulesModule = Import-Module -Name $modulePath -PassThru -ErrorAction Stop }
    $fixturePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'tests\Fixtures\PSNetRules.TestFixtures.ps1'
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) { throw "Shared test fixture file not found: $fixturePath" }
    . $fixturePath
    Assert-NRAdministrator

    $runId = [string]$env:NETRULES_INTEGRATION_RUN_ID
    if ([string]::IsNullOrWhiteSpace($runId)) { throw 'Run integration tests through integration-tests\Run-IntegrationTests.ps1.' }
    $script:FirewallIntegrationName = [string]$env:NETRULES_INTEGRATION_FIREWALL_NAME
    $script:NrptIntegrationLogicalId = [string]$env:NETRULES_INTEGRATION_NRPT_ID
    $script:NrptIntegrationNamespace = [string]$env:NETRULES_INTEGRATION_NRPT_NAMESPACE
    $script:DynamicKeywordIntegrationId = [string]$env:NETRULES_INTEGRATION_DYNAMIC_ID
    $script:DynamicKeywordIntegrationName = [string]$env:NETRULES_INTEGRATION_DYNAMIC_KEYWORD
    foreach ($requiredValue in @($script:FirewallIntegrationName, $script:NrptIntegrationLogicalId, $script:NrptIntegrationNamespace, $script:DynamicKeywordIntegrationId, $script:DynamicKeywordIntegrationName)) {
        if ([string]::IsNullOrWhiteSpace($requiredValue)) { throw 'The integration test runner did not provide all test resource identifiers.' }
    }

    function Invoke-NRIntegrationPrivateFunction {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)] [string] $Name,
            [hashtable] $Parameters = @{}
        )
        $module = $script:NetRulesModule
        if ($null -eq $module) { throw 'PSNetRules module is not loaded.' }
        & $module {
            param($PrivateName, $PrivateParameters)
            & $PrivateName @PrivateParameters
        } $Name $Parameters
    }
}

Describe 'netrules Windows integration' -Tag 'WindowsIntegration' {
    It 'captures real PersistentStore rules, filters, profiles and local NRPT rules' {
        $statePath = Join-Path $TestDrive 'integration.state.json'
        $snapshot = Get-NRCurrentState -StatePath $statePath
        (Assert-NRConfiguration -Configuration $snapshot) | Should-Be $true
        @(@('Domain', 'Private', 'Public') | Where-Object { $null -eq $snapshot.firewallProfiles[$_] }).Count | Should-Be 0
        foreach ($rule in $snapshot.firewallRules) {
            @(@('address', 'port', 'application', 'service', 'interface', 'interfaceType', 'security') |
                Where-Object { $null -eq $rule.filters[$_] }).Count | Should-Be 0
        }
    }

    It 'creates, captures, updates and deletes one actual PersistentStore Firewall rule' {
        $name = $script:FirewallIntegrationName
        Write-Host "[CREATE] Firewall rule Name='$name' Store='PersistentStore' Enabled='False' Profile='Private' Direction='Inbound' Action='Allow' Protocol='TCP' LocalPort='54321'"
        try {
            $initial = New-NRFixtureFirewallRuleRecord -Name $name -DisplayName "$name original" `
                -Description 'Temporary netrules integration test rule' -Group $null -Enabled 'False' -LocalPort '54321'
            New-NRFirewallRule -Name $name -Parameters (ConvertTo-NRFirewallParameters $initial)

            $native = @(Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop)
            $native.Count | Should-Be 1
            $captured = @(Get-NRFirewallRules | Where-Object { $_.name -eq $name })
            $captured.Count | Should-Be 1
            @($captured[0].filters.port.LocalPort -contains '54321') | Should-Be $true

            $updated = $initial | ConvertTo-Json -Depth 100 | ConvertFrom-Json
            Write-Host "[UPDATE] Firewall rule Name='$name': DisplayName='$name updated', LocalPort='54322'"
            $updated.rule.DisplayName = "$name updated"
            $updated.filters.port.LocalPort = @('54322')
            Set-NRFirewallRule -Name $name -Parameters (ConvertTo-NRFirewallParameters $updated)

            $after = @(Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop)
            $after.Count | Should-Be 1
            $after[0].DisplayName | Should-Be "$name updated"
            # Join the bulk Filter results to the Rule by InstanceID, as Capture
            # does. Some Windows builds expose the Rule identifier through Name,
            # so the associated-rule parameter is not reliable for this check.
            Write-Host "[VERIFY] Firewall port filter InstanceID='$name' expected LocalPort='54322'"
            $portFilters = @(
                Get-NetFirewallPortFilter -All -PolicyStore PersistentStore -ErrorAction Stop |
                    Where-Object { [string]$_.InstanceID -eq $name }
            )
            $portFilters.Count | Should-Be 1
            @($portFilters[0].LocalPort -contains '54322') | Should-Be $true

            Write-Host "[DELETE] Firewall rule Name='$name' Store='PersistentStore'"
            Remove-NRStaleFirewallRules -CurrentRulesByName @{ $name = $after[0] } -DesiredRules @{}

            # A name-targeted query can report CmdletizationQuery_NotFound_InstanceID
            # for an absent Rule. Enumerate PersistentStore and match the Name locally.
            Write-Host "[VERIFY DELETE] Searching PersistentStore for Name='$name'"
            $remainingRules = @(
                Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
                    Where-Object { [string]$_.Name -ceq $name }
            )
            $remainingRules.Count | Should-Be 0
        }
        finally {
            # The runner checked this unique test Name before the suite started.
            $leftoverRule = @(Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
            if ($leftoverRule.Count -gt 0) {
                Write-Host "[CLEANUP] Firewall rule Name='$name' Store='PersistentStore'"
                Remove-NetFirewallRule -Name $name -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop
            }
        }
    }

    It 'creates, captures and deletes one actual local NRPT rule with a sidecar identity' {
        $logicalId = $script:NrptIntegrationLogicalId
        $namespace = $script:NrptIntegrationNamespace
        Write-Host "[CREATE] Local NRPT id='$logicalId' Namespace='$namespace' NameServers='127.0.0.1'"
        $statePath = Join-Path $TestDrive 'nrpt-integration.state.json'
        $stateMap = @{}
        try {
            $record = [pscustomobject][ordered]@{
                id = $logicalId
                Namespace = @($namespace)
                IPsecTrustAuthority = $null
                DANameServers = $null
                DAEnable = $false
                DAIPsecEncryptionType = $null
                DAIPsecRequired = $false
                DAProxyServerName = $null
                DAProxyType = $null
                NameServers = @('127.0.0.1')
                NameEncoding = 'Punycode'
                DnsSecEnable = $false
                DnsSecIPsecEncryptionType = $null
                DnsSecIPsecRequired = $false
                DnsSecValidationRequired = $false
                DisplayName = $logicalId
                Comment = 'Temporary netrules integration test rule'
            }

            Add-NRNrptRuleAndTrack -LogicalId $logicalId -Record $record -StateMap $stateMap -StatePath $statePath
            $windowsName = $stateMap[$logicalId]
            [string]::IsNullOrWhiteSpace($windowsName) | Should-Be $false

            $native = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Name -eq $windowsName })
            $native.Count | Should-Be 1
            @($native[0].Namespace -contains $namespace) | Should-Be $true
            @($native[0].NameServers -contains '127.0.0.1') | Should-Be $true

            # Verify that a native cmdlet object and its shared test fixture
            # produce the same result through the production projection function.
            $nrptFixture = New-NRFixtureNrptWindowsRule -InputObject $native[0]
            $nativeProjection = Invoke-NRIntegrationPrivateFunction -Name ConvertTo-NRNrptRecord -Parameters @{
                Rule = $native[0]; LogicalId = $logicalId
            }
            $fixtureProjection = Invoke-NRIntegrationPrivateFunction -Name ConvertTo-NRNrptRecord -Parameters @{
                Rule = $nrptFixture; LogicalId = $logicalId
            }
            (ConvertTo-NRCanonicalJson $fixtureProjection) | Should-Be (ConvertTo-NRCanonicalJson $nativeProjection)
            Write-Host "[MOCK COMPATIBILITY] NRPT native object and PSCustomObject fixture match for '$logicalId'."

            $captured = @(Get-NRNrptRules -IdByWindowsName @{ $windowsName = $logicalId } | Where-Object { $_.id -eq $logicalId })
            $captured.Count | Should-Be 1
            @($captured[0].Namespace -contains $namespace) | Should-Be $true
            (ConvertTo-NRCanonicalJson $captured[0]) | Should-Be (ConvertTo-NRCanonicalJson $nativeProjection)

            # NRPT updates recreate the Windows rule. Verify that the old
            # declaration is replaced and the State mapping tracks the new Name.
            Write-Host "[RECREATE] Local NRPT old Windows Name='$windowsName' Namespace='$namespace'; new NameServers='127.0.0.2'"
            $record.NameServers = @('127.0.0.2')
            Sync-NRNrptRule -LogicalId $logicalId -DesiredRecord $record `
                -CurrentById @{ $logicalId = $native[0] } -NameById @{ $logicalId = $windowsName } `
                -StateMap $stateMap -StatePath $statePath
            $updatedWindowsName = [string]$stateMap[$logicalId]
            ($updatedWindowsName -ceq $windowsName) | Should-Be $false

            $updatedNative = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Name -eq $updatedWindowsName })
            $updatedNative.Count | Should-Be 1
            @($updatedNative[0].NameServers -contains '127.0.0.2') | Should-Be $true
            @($updatedNative[0].NameServers -contains '127.0.0.1') | Should-Be $false

            $currentById = @{ $logicalId = $updatedNative[0] }
            $nameById = @{ $logicalId = $updatedWindowsName }
            Write-Host "[DELETE] Local NRPT Windows Name='$updatedWindowsName' Namespace='$namespace'"
            Remove-NRStaleNrptRules -CurrentById $currentById -NameById $nameById `
                -DesiredRules @{} -StateMap $stateMap -StatePath $statePath

            @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Name -eq $updatedWindowsName }).Count | Should-Be 0
            (Read-NRStateFile -Path $statePath).nrptRules.Count | Should-Be 0
        }
        finally {
            # Remove only NRPT rules carrying this run's unique Namespace.
            $leftovers = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
                Where-Object { @($_.Namespace) -contains $namespace })
            foreach ($leftover in $leftovers) {
                Write-Host "[CLEANUP] Local NRPT Windows Name='$($leftover.Name)' Namespace='$namespace'"
                Remove-DnsClientNrptRule -Name $leftover.Name -Force -ErrorAction Stop
            }
        }
    }

    It 'reads all real PersistentStore Firewall Profile settings without modifying them' {
        $profiles = Get-NRFirewallProfiles
        $profileNames = @('Domain', 'Private', 'Public')
        @($profileNames | Where-Object { $null -eq $profiles[$_] }).Count | Should-Be 0
        Write-Host '[READ ONLY] Firewall Profiles Domain, Private, Public; no Set-NetFirewallProfile call.'
    }

    It 'creates, updates, reads and deletes one real static Dynamic Keyword Address' {
        $id = $script:DynamicKeywordIntegrationId
        $keyword = $script:DynamicKeywordIntegrationName
        Write-Host "[CREATE] Dynamic Keyword Address Id='$id' Keyword='$keyword' Addresses='192.0.2.10' AutoResolve='False'"
        try {
            $record = [pscustomobject]@{
                id = $id
                Keyword = $keyword
                Addresses = '192.0.2.10'
                AutoResolve = $false
            }
            New-NRFirewallDynamicKeyword -Record $record

            $native = @(Get-NetFirewallDynamicKeywordAddress -All -PolicyStore PersistentStore -ErrorAction Stop |
                Where-Object { [string]$_.Id -eq $id })
            $native.Count | Should-Be 1
            $native[0].Keyword | Should-Be $keyword
            $native[0].Addresses | Should-Be '192.0.2.10'

            # Verify that a native cmdlet object and its shared test fixture
            # produce the same result through the production projection function.
            $dynamicFixture = New-NRFixtureDynamicKeywordAddress -InputObject $native[0]
            $nativeProjection = Invoke-NRIntegrationPrivateFunction `
                -Name ConvertTo-NRFirewallDynamicKeywordAddressRecord -Parameters @{ Address = $native[0] }
            $fixtureProjection = Invoke-NRIntegrationPrivateFunction `
                -Name ConvertTo-NRFirewallDynamicKeywordAddressRecord -Parameters @{ Address = $dynamicFixture }
            (ConvertTo-NRCanonicalJson $fixtureProjection) | Should-Be (ConvertTo-NRCanonicalJson $nativeProjection)
            $captured = @(Get-NRFirewallDynamicKeywordAddresses | Where-Object { $_.id -eq $id })
            $captured.Count | Should-Be 1
            (ConvertTo-NRCanonicalJson $captured[0]) | Should-Be (ConvertTo-NRCanonicalJson $nativeProjection)
            Write-Host "[MOCK COMPATIBILITY] Dynamic Keyword Address native object, PSCustomObject fixture, and capture adapter match for '$id'."

            Write-Host "[UPDATE] Dynamic Keyword Address Id='$id' Keyword='$keyword' Addresses='192.0.2.20'"
            $updated = [pscustomobject]@{
                id = $id
                Keyword = $keyword
                Addresses = '192.0.2.20'
                AutoResolve = $false
            }
            Update-NRFirewallDynamicKeyword -CurrentRecord $native[0] -DesiredRecord $updated -Id $id

            $after = @(Get-NetFirewallDynamicKeywordAddress -All -PolicyStore PersistentStore -ErrorAction Stop |
                Where-Object { [string]$_.Id -eq $id })
            $after.Count | Should-Be 1
            $after[0].Addresses | Should-Be '192.0.2.20'

            Write-Host "[DELETE] Dynamic Keyword Address Id='$id' Keyword='$keyword'"
            Remove-NetFirewallDynamicKeywordAddress -Id $id -Confirm:$false -ErrorAction Stop
            @(Get-NetFirewallDynamicKeywordAddress -All -PolicyStore PersistentStore -ErrorAction Stop |
                Where-Object { [string]$_.Id -eq $id }).Count | Should-Be 0
        }
        finally {
            $leftoverAddress = @(Get-NetFirewallDynamicKeywordAddress -All -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Where-Object { [string]$_.Id -eq $id })
            if ($leftoverAddress.Count -gt 0) {
                Write-Host "[CLEANUP] Dynamic Keyword Address Id='$id' Keyword='$keyword'"
                Remove-NetFirewallDynamicKeywordAddress -Id $id -Confirm:$false -ErrorAction Stop
            }
        }
    }

}
