#requires -Version 5.1

BeforeAll {
    if ($env:OS -ne 'Windows_NT') {
        throw 'Windows contract tests require Windows. No system changes are made.'
    }

    Import-Module NetSecurity -ErrorAction Stop
    Import-Module DnsClient -ErrorAction Stop
    $repositoryRoot = Split-Path -Parent $PSScriptRoot
    # Pester module-scoped mocks require one unambiguous PSNetRules instance.
    Get-Module -Name PSNetRules | Remove-Module -Force -ErrorAction SilentlyContinue
    $script:NetRulesModule = Import-Module (Join-Path $repositoryRoot 'src\PSNetRules.psm1') -Force -PassThru -ErrorAction Stop
    $fixturePath = Join-Path $repositoryRoot 'tests\Fixtures\PSNetRules.TestFixtures.ps1'
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) { throw "Shared test fixture file not found: $fixturePath" }
    . $fixturePath
    Assert-NRAdministrator

    function Invoke-NRContractPrivateFunction {
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

Describe 'netrules Windows cmdlet parameter contract' {
    It 'maps every Firewall rule and filter parameter to a real New-NetFirewallRule parameter' {
        $command = Get-Command New-NetFirewallRule -ErrorAction Stop
        $parameters = ConvertTo-NRFirewallParameters -Record (New-NRFixtureFirewallRuleRecord -Name 'ContractRule' -DisplayName 'Contract Rule' -Enabled 'False' -LocalPort '54321')
        foreach ($parameterName in $parameters.Keys) {
            $command.Parameters.ContainsKey([string]$parameterName) | Should-Be $true -Because "New-NetFirewallRule must expose '$parameterName'"
        }
        $command.Parameters.ContainsKey('PolicyStore') | Should-Be $true
        $command.Parameters.ContainsKey('Name') | Should-Be $true
    }

    It 'maps mutable Firewall update parameters to real Set-NetFirewallRule parameters' {
        $command = Get-Command Set-NetFirewallRule -ErrorAction Stop
        $parameters = ConvertTo-NRFirewallParameters -Record (New-NRFixtureFirewallRuleRecord -Name 'ContractRule' -DisplayName 'Contract Rule' -Enabled 'False' -LocalPort '54321')
        if ($parameters.ContainsKey('DisplayName')) {
            $parameters['NewDisplayName'] = $parameters['DisplayName']
            $parameters.Remove('DisplayName')
        }
        foreach ($field in @('Group', 'Platform', 'Owner')) { $parameters.Remove($field) }
        foreach ($parameterName in $parameters.Keys) {
            $command.Parameters.ContainsKey([string]$parameterName) | Should-Be $true -Because "Set-NetFirewallRule must expose '$parameterName'"
        }
        $command.Parameters.ContainsKey('Name') | Should-Be $true
        $command.Parameters.ContainsKey('PolicyStore') | Should-Be $true
    }

    It 'uses real Firewall filter cmdlet parameters, bulk enumeration, and the PersistentStore selector' {
        $commands = @(
            'Get-NetFirewallAddressFilter', 'Get-NetFirewallPortFilter',
            'Get-NetFirewallApplicationFilter', 'Get-NetFirewallServiceFilter',
            'Get-NetFirewallInterfaceFilter', 'Get-NetFirewallInterfaceTypeFilter',
            'Get-NetFirewallSecurityFilter'
        )
        foreach ($commandName in $commands) {
            $command = Get-Command $commandName -ErrorAction Stop
            $command.Parameters.ContainsKey('AssociatedNetFirewallRule') | Should-Be $true -Because "$commandName must expose AssociatedNetFirewallRule"
            $command.Parameters.ContainsKey('All') | Should-Be $true -Because "$commandName must expose -All for bulk filter retrieval"
            $command.Parameters.ContainsKey('PolicyStore') | Should-Be $true
        }
    }

    It 'reuses captured Native PersistentStore objects for comparison and queries SystemDefaults separately' {
        $firewallCapture = Get-NRFirewallRules -IncludeComparisonSource
        $persistent = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore -CaptureSource $firewallCapture.ComparisonSource
        $defaults = Get-NRFirewallRuleComparisonInventory -PolicyStore SystemDefaults

        $firewallCapture.Records.Count | Should-Be $persistent.RuleCount
        $persistent.Entries.Count | Should-Be $persistent.RuleCount
        $defaults.Entries.Count | Should-Be $defaults.RuleCount
        @($persistent.Entries | Where-Object { -not $_.IsComplete }).Count | Should-Be 0
        @($defaults.Entries | Where-Object { -not $_.IsComplete }).Count | Should-Be 0
        (Invoke-NRContractPrivateFunction -Name 'Get-NRMapByKey' -Parameters @{ Items = @($persistent.Entries); KeyProperty = 'Name' }).Count | Should-Be $persistent.RuleCount
        (Invoke-NRContractPrivateFunction -Name 'Get-NRMapByKey' -Parameters @{ Items = @($defaults.Entries); KeyProperty = 'Name' }).Count | Should-Be $defaults.RuleCount
    }

    It 'runs diff in Windows PowerShell 5.1 and writes only candidate text to standard output' {
        $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
            throw "Windows PowerShell 5.1 executable was not found: $windowsPowerShell"
        }

        $repositoryRoot = Split-Path -Parent $PSScriptRoot
        $scriptPath = Join-Path $repositoryRoot 'PSNetRules.ps1'
        $configurationPath = Join-Path $TestDrive 'winps51-diff.json'
        $snapshotPath = Join-Path $TestDrive 'winps51-diff.snapshot.json'
        $stdoutPath = Join-Path $TestDrive 'winps51-diff.stdout.txt'
        $stderrPath = Join-Path $TestDrive 'winps51-diff.stderr.txt'

        $profiles = [pscustomobject][ordered]@{
            Domain = New-NRFixtureFirewallProfile
            Private = New-NRFixtureFirewallProfile
            Public = New-NRFixtureFirewallProfile
        }
        $desired = [pscustomobject][ordered]@{
            schemaVersion = 1
            firewallProfiles = $profiles
            firewallDynamicKeywordAddresses = @()
            firewallRules = @()
            nrptRules = @()
        }
        $capturedConfiguration = [pscustomobject][ordered]@{
            schemaVersion = 1
            firewallProfiles = $profiles
            firewallDynamicKeywordAddresses = @()
            firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'ContractRule' -DisplayName 'Contract Rule' -Enabled 'False' -LocalPort '54321'))
            nrptRules = @()
        }
        $persistentEntry = [pscustomobject]@{
            Name = 'ContractRule'
            IsComplete = $true
            MissingFilters = @()
            FilterIssues = @()
            Fields = @{}
        }
        $snapshot = [pscustomobject][ordered]@{
            schemaVersion = 1
            capturedAt = (Get-Date).ToString('o')
            computerName = $env:COMPUTERNAME
            configuration = $capturedConfiguration
            comparison = [pscustomobject][ordered]@{
                persistentStore = [pscustomobject]@{
                    PolicyStore = 'PersistentStore'
                    RuleCount = 1
                    Entries = @($persistentEntry)
                    BulkFilterWarnings = @()
                }
                systemDefaults = [pscustomobject]@{
                    PolicyStore = 'SystemDefaults'
                    RuleCount = 0
                    Entries = @()
                    BulkFilterWarnings = @()
                }
                excludedProperties = @('Name', 'InstanceID', 'PolicyStore')
                arraySemantics = 'Array order is ignored; duplicate elements are retained.'
                stringSemantics = 'String values are compared case-sensitively.'
            }
        }

        [System.IO.File]::WriteAllText($configurationPath, (ConvertTo-Json -InputObject $desired -Depth 100))
        [System.IO.File]::WriteAllText($snapshotPath, (ConvertTo-Json -InputObject $snapshot -Depth 100))

        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $windowsPowerShell
        $startInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" diff "{1}"' -f $scriptPath, $configurationPath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::Start($startInfo)
        try {
            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()
            $process.WaitForExit()
            [System.IO.File]::WriteAllText($stdoutPath, $stdout)
            [System.IO.File]::WriteAllText($stderrPath, $stderr)
            $process.ExitCode | Should-Be 0 -Because $stderr
            $stdout | Should-MatchString '\[NewCandidate\].*ContractRule'
            $stdout | Should-MatchString 'Other managed resources: No changes\.'
            $stdout | Should-NotMatchString '"excludedProperties"|"arraySemantics"|"stringSemantics"|"Rule\.CreationClassName"'
            [string]::IsNullOrEmpty($stderr) | Should-Be $true
        }
        finally {
            if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
            $process.Dispose()
        }
    }

    It 'uses real cmdlet parameters for Firewall and NRPT reads and deletes' {
        $getFirewall = Get-Command Get-NetFirewallRule -ErrorAction Stop
        $getProfile = Get-Command Get-NetFirewallProfile -ErrorAction Stop
        $getDynamic = Get-Command Get-NetFirewallDynamicKeywordAddress -ErrorAction Stop
        $removeFirewall = Get-Command Remove-NetFirewallRule -ErrorAction Stop
        $getNrpt = Get-Command Get-DnsClientNrptRule -ErrorAction Stop
        $removeNrpt = Get-Command Remove-DnsClientNrptRule -ErrorAction Stop
        $removeDynamic = Get-Command Remove-NetFirewallDynamicKeywordAddress -ErrorAction Stop

        foreach ($command in @($getFirewall, $getProfile, $getDynamic)) {
            $command.Parameters.ContainsKey('PolicyStore') | Should-Be $true -Because "$($command.Name) must expose PolicyStore"
        }
        $removeFirewall.Parameters.ContainsKey('Name') | Should-Be $true
        $getNrpt.Parameters.ContainsKey('GpoName') | Should-Be $true
        $removeNrpt.Parameters.ContainsKey('Name') | Should-Be $true
        $removeNrpt.Parameters.ContainsKey('Force') | Should-Be $true
        $removeDynamic.Parameters.ContainsKey('Id') | Should-Be $true
    }

    It 'maps every Firewall Profile property to real Set-NetFirewallProfile parameters' {
        $command = Get-Command Set-NetFirewallProfile -ErrorAction Stop
        $parameters = ConvertTo-NRProfileParameters -Record (New-NRFixtureFirewallProfile)
        foreach ($parameterName in $parameters.Keys) {
            $command.Parameters.ContainsKey([string]$parameterName) | Should-Be $true -Because "Set-NetFirewallProfile must expose '$parameterName'"
        }
    }

    It 'maps NRPT creation fields to real Add-DnsClientNrptRule parameters' {
        $command = Get-Command Add-DnsClientNrptRule -ErrorAction Stop
        $parameters = ConvertTo-NRNrptParameters -Record (New-NRFixtureNrptRuleRecord -Id 'contract-nrpt' -Namespace @('.contract.invalid') -Server '127.0.0.1' -DisplayName 'Contract DNS') -ForAdd
        foreach ($parameterName in $parameters.Keys) {
            $command.Parameters.ContainsKey([string]$parameterName) | Should-Be $true -Because "Add-DnsClientNrptRule must expose '$parameterName'"
        }
        $command.Parameters.ContainsKey('PassThru') | Should-Be $true
    }

    It 'maps Dynamic Keyword Address creation and update parameters to real cmdlet definitions' {
        $newCommand = Get-Command New-NetFirewallDynamicKeywordAddress -ErrorAction Stop
        $updateCommand = Get-Command Update-NetFirewallDynamicKeywordAddress -ErrorAction Stop
        $record = [pscustomobject]@{
            id = '{11111111-1111-1111-1111-111111111111}'
            Keyword = 'Static'
            Addresses = '192.0.2.1'
            AutoResolve = $false
        }
        foreach ($parameterName in (New-NRDynamicKeywordParameters $record).Keys) {
            $newCommand.Parameters.ContainsKey([string]$parameterName) | Should-Be $true -Because "New-NetFirewallDynamicKeywordAddress must expose '$parameterName'"
        }
        foreach ($parameterName in @('Id', 'Addresses', 'Append')) {
            $updateCommand.Parameters.ContainsKey($parameterName) | Should-Be $true -Because "Update-NetFirewallDynamicKeywordAddress must expose '$parameterName'"
        }
    }
}

Describe 'netrules Windows runtime object and Mock compatibility contract' {
    It 'reads all three real PersistentStore profiles and produces the same projection from PSCustomObject fixtures' {
        $nativeProfiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
        $capturedProfiles = Get-NRFirewallProfiles
        $profileFixtures = @()
        foreach ($profileName in @('Domain', 'Private', 'Public')) {
            $matching = @($nativeProfiles | Where-Object { [string]$_.Name -eq $profileName })
            $matching.Count | Should-Be 1
            $capturedProfiles.Contains($profileName) | Should-Be $true
            $fixture = New-NRFixtureFirewallProfile -InputObject $matching[0]
            $fixture.Name | Should-Be $profileName
            foreach ($fieldName in @($fixture.PSObject.Properties.Name | Where-Object { $_ -ne 'Name' })) {
                (Test-NRProperty -InputObject $fixture -Name $fieldName) | Should-Be (Test-NRProperty -InputObject $matching[0] -Name $fieldName)
            }
            $profileFixtures = @($profileFixtures) + @($fixture)
        }
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { $profileFixtures }
        $mockProfiles = Get-NRFirewallProfiles
        (ConvertTo-NRCanonicalJson $mockProfiles) | Should-Be (ConvertTo-NRCanonicalJson $capturedProfiles)
    }

    It 'converts a real Firewall CIM rule and its seven native filters identically to the PSCustomObject fixtures used by Unit tests' {
        $nativeRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
        if ($nativeRules.Count -eq 0) {
            Set-ItResult -Skipped -Because 'The local PersistentStore contains no Firewall rules to use as a native contract sample.'
            return
        }

        $nativeRule = $nativeRules[0]
        $sampleName = [string]$nativeRule.Name
        [string]::IsNullOrWhiteSpace($sampleName) | Should-Be $false
        $mockRule = New-NRFixtureFirewallRuleObject -InputObject $nativeRule
        $nativeIndex = @{}
        $mockIndex = @{}

        foreach ($spec in @(Get-NRFirewallFilterSpecs)) {
            $nativeFilters = @(& $spec.Cmdlet -All -PolicyStore PersistentStore -ErrorAction Stop |
                Where-Object { [string]$_.InstanceID -eq $sampleName })
            $nativeFilters.Count | Should-Be 1 -Because "A native $($spec.JsonName) filter must exist for '$sampleName'"
            $nativeFilter = $nativeFilters[0]
            $fixtureType = $spec.JsonName.Substring(0, 1).ToUpperInvariant() + $spec.JsonName.Substring(1)
            $mockFilter = New-NRFixtureFirewallFilter -Type $fixtureType -InputObject $nativeFilter

            $nativeFilterRecord = Invoke-NRContractPrivateFunction -Name ConvertTo-NRFirewallFilterRecord -Parameters @{
                FilterItem = $nativeFilter; Spec = $spec
            }
            $mockFilterRecord = Invoke-NRContractPrivateFunction -Name ConvertTo-NRFirewallFilterRecord -Parameters @{
                FilterItem = $mockFilter; Spec = $spec
            }
            (ConvertTo-NRCanonicalJson $mockFilterRecord) | Should-Be (ConvertTo-NRCanonicalJson $nativeFilterRecord)
            $nativeIndex[$spec.JsonName] = @{ $sampleName = $nativeFilterRecord }
            $mockIndex[$spec.JsonName] = @{ $sampleName = $mockFilterRecord }
        }

        $nativeRecord = Invoke-NRContractPrivateFunction -Name ConvertTo-NRFirewallRuleRecord -Parameters @{
            Rule = $nativeRule; Name = $sampleName; FilterIndex = $nativeIndex
        }
        $mockCompatibleRecord = Invoke-NRContractPrivateFunction -Name ConvertTo-NRFirewallRuleRecord -Parameters @{
            Rule = $mockRule; Name = $sampleName; FilterIndex = $mockIndex
        }
        (ConvertTo-NRCanonicalJson $mockCompatibleRecord) | Should-Be (ConvertTo-NRCanonicalJson $nativeRecord)
    }

    It 'exposes every valued record field in comparison entries built from real rules' {
        $firewallCapture = Get-NRFirewallRules -IncludeComparisonSource
        if ($firewallCapture.Records.Count -eq 0) {
            Set-ItResult -Skipped -Because 'The local PersistentStore contains no Firewall rules to use as a native contract sample.'
            return
        }
        $persistent = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore -CaptureSource $firewallCapture.ComparisonSource
        $recordsByName = @{}
        foreach ($record in $firewallCapture.Records) { $recordsByName[[string]$record.name] = $record }

        # The vocabulary contract: whatever field a record read a value for,
        # the comparison entry for the same rule must expose under the same
        # field name. Entry values intentionally keep the raw CIM
        # representation (numeric enums, null for unrestricted addresses),
        # so only names are contracted here, not value representations.
        # Fields the record left null impose no requirement (the underlying
        # instance may not carry the property). All violations are collected
        # so one run reports every gap.
        $violations = New-Object 'System.Collections.Generic.List[string]'
        foreach ($entry in $persistent.Entries) {
            $record = $recordsByName[[string]$entry.Name]
            if ($null -eq $record) { continue }
            $missingSections = @($entry.MissingFilters)
            foreach ($spec in @(Get-NRFirewallFilterSpecs)) {
                $section = $spec.JsonName.Substring(0, 1).ToUpperInvariant() + $spec.JsonName.Substring(1)
                if ($missingSections -contains $section) { continue }
                $recordFilter = Get-NRProperty (Get-NRProperty $record 'filters') $spec.JsonName
                foreach ($field in $spec.Fields) {
                    $recordValue = Get-NRProperty $recordFilter $field
                    if ($null -eq $recordValue) { continue }
                    $key = "$section.$field"
                    if (-not $entry.Fields.Contains($key)) {
                        $violations.Add("$($entry.Name): missing '$key'")
                    }
                }
            }
        }
        $shown = @($violations | Select-Object -First 10) -join '; '
        if ($violations.Count -gt 10) { $shown += "; and $($violations.Count - 10) more" }
        $violations.Count | Should-Be 0 -Because $shown
    }

    It 'finds the program of a real rule through the snapshot search conversion' {
        $firewallCapture = Get-NRFirewallRules -IncludeComparisonSource
        $persistent = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore -CaptureSource $firewallCapture.ComparisonSource
        $snapshot = [pscustomobject]@{
            comparison = [pscustomobject]@{ persistentStore = $persistent }
        }
        $searchable = @(Invoke-NRContractPrivateFunction -Name 'Get-NRSearchableFirewallRule' -Parameters @{
            Source = 'Snapshot'; Snapshot = $snapshot
        })
        $searchable.Count | Should-Be $persistent.Entries.Count

        $sample = $null
        foreach ($record in $firewallCapture.Records) {
            $program = [string](Get-NRProperty (Get-NRProperty (Get-NRProperty $record 'filters') 'application') 'Program')
            if (-not [string]::IsNullOrWhiteSpace($program) -and $program -ne 'Any') {
                $sample = [pscustomobject]@{ Name = [string]$record.name; Program = $program }
                break
            }
        }
        if ($null -eq $sample) {
            Set-ItResult -Skipped -Because 'No local Firewall rule has a program path to use as a search contract sample.'
            return
        }
        $match = @($searchable | Where-Object { $_.Name -eq $sample.Name })
        $match.Count | Should-Be 1
        [string]$match[0].Fields['Application.Program'] | Should-Be $sample.Program
    }

    It 'projects a real NRPT CIM object identically when represented by the PSCustomObject fixture used by Unit mocks' {
        $nativeRules = @(Get-DnsClientNrptRule -ErrorAction Stop)
        if ($nativeRules.Count -eq 0) {
            Set-ItResult -Skipped -Because 'No local NRPT sample exists. This read-only suite will not create one; Integration tests compare a run-scoped real NRPT object with its PSCustomObject fixture.'
            return
        }

        $nativeRule = $nativeRules[0]
        $logicalId = 'contract-' + [guid]::NewGuid().ToString('N')
        $stateMap = @{}
        $stateMap[[string]$nativeRule.Name] = $logicalId
        $nativeProjection = @(Get-NRNrptRules -IdByWindowsName $stateMap | Where-Object { $_.id -eq $logicalId })
        $nativeProjection.Count | Should-Be 1

        $nrptFixture = New-NRFixtureNrptWindowsRule -InputObject $nativeRule
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($nrptFixture) }
        $mockProjection = @(Get-NRNrptRules -IdByWindowsName $stateMap | Where-Object { $_.id -eq $logicalId })
        $mockProjection.Count | Should-Be 1
        (ConvertTo-NRCanonicalJson $mockProjection[0]) | Should-Be (ConvertTo-NRCanonicalJson $nativeProjection[0])
    }

    It 'projects real Dynamic Keyword Address objects identically when represented by PSCustomObject fixtures' {
        $nativeItems = @(Get-NetFirewallDynamicKeywordAddress -All -PolicyStore PersistentStore -ErrorAction Stop)
        if ($nativeItems.Count -eq 0) {
            Set-ItResult -Skipped -Because 'No local Dynamic Keyword Address sample exists. This read-only suite will not create one; Integration tests compare a run-scoped real object with its PSCustomObject fixture.'
            return
        }

        $nativeProjection = @(Get-NRFirewallDynamicKeywordAddresses)
        $fixtures = @(
            foreach ($nativeItem in $nativeItems) {
                New-NRFixtureDynamicKeywordAddress -InputObject $nativeItem
            }
        )
        $dynamicFixtures = $fixtures
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { $dynamicFixtures }
        $mockProjection = @(Get-NRFirewallDynamicKeywordAddresses)
        (ConvertTo-NRCanonicalJson $mockProjection) | Should-Be (ConvertTo-NRCanonicalJson $nativeProjection)
    }
}
