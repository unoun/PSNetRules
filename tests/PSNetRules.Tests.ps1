BeforeAll {
    . (Join-Path $PSScriptRoot 'Common\PSNetRules.TestSetup.ps1')
}

Describe 'PSNetRules module structure' {
    It 'defines every exported function and every module-internal command reference' {
        $moduleSource = [System.IO.File]::ReadAllText($script:NetRulesModule.Path)
        $definitionMatches = [regex]::Matches($moduleSource, '(?im)^\s*function\s+([\w-]+)')
        $definedFunctions = @($definitionMatches | ForEach-Object { $_.Groups[1].Value })
        $uniqueFunctions = @($definedFunctions | Sort-Object -Unique)
        $duplicateFunctions = @($definedFunctions | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })

        $exportMatch = [regex]::Match($moduleSource, '(?is)Export-ModuleMember\s+-Function\s+@\((.*?)\)')
        if (-not $exportMatch.Success) { throw 'Export-ModuleMember function list was not found.' }
        $exportMatches = [regex]::Matches($exportMatch.Groups[1].Value, "'([^']+)'")
        $exportedFunctions = @($exportMatches | ForEach-Object { $_.Groups[1].Value })
        $missingExports = @($exportedFunctions | Where-Object { $_ -notin $uniqueFunctions })

        $internalCommandMatches = [regex]::Matches($moduleSource, '\b(?:Assert|Get|Set|Test|New|Remove|Write|Read|Resolve|Invoke|Add|Update|Convert|Format|Move|Restore|Start|Stop|Complete|Clear|Initialize|Import|Export|Find|Compare|Copy|Reset|Save|Select|Use|Sync|Ensure|Build)-NR[A-Za-z0-9_-]*\b')
        $internalCommands = @($internalCommandMatches | ForEach-Object { $_.Value } | Sort-Object -Unique)
        # Commands defined inside the generated apply script, not in this module:
        # Add-NRGeneratedNrptStateBlock emits 'function Save-NRGeneratedNrptState' into
        # the generated script, so its NRPT commands can update the state file
        # without importing the module.
        $generatedScriptOnlyCommands = @('Save-NRGeneratedNrptState')
        $missingInternalCommands = @($internalCommands | Where-Object { $_ -notin $uniqueFunctions -and $_ -notin $generatedScriptOnlyCommands })

        $problems = @()
        if ($duplicateFunctions.Count -gt 0) { $problems += ('Duplicate function definitions: ' + ($duplicateFunctions -join ', ')) }
        if ($missingExports.Count -gt 0) { $problems += ('Exported functions without definitions: ' + ($missingExports -join ', ')) }
        if ($missingInternalCommands.Count -gt 0) { $problems += ('Referenced internal commands without definitions: ' + ($missingInternalCommands -join ', ')) }
        if ($problems.Count -gt 0) { throw ($problems -join [Environment]::NewLine) }
    }
}

Describe 'netrules property and serialization primitives' {
    It 'loads exactly one PSNetRules module instance from the repository source' {
        $loadedNetRulesModules = @(Get-Module -Name PSNetRules)
        $loadedNetRulesModules.Count | Should-Be 1
        $loadedNetRulesModules[0].Path | Should-Be $script:NetRulesModule.Path
    }

    It 'reads dictionary and object properties while preserving array values' {
        $dictionary = @{ Items = @('one', 'two') }
        $object = [pscustomobject]@{ Value = 42 }
        (Get-NRProperty $dictionary 'Items').Count | Should-Be 2
        (Get-NRProperty $object 'Value') | Should-Be 42
        (Get-NRProperty $object 'Missing') | Should-Be $null
    }

    It 'distinguishes existing null properties from missing properties' {
        $object = [pscustomobject]@{ Present = $null }
        (Test-NRProperty $object 'Present') | Should-Be $true
        (Test-NRProperty $object 'Missing') | Should-Be $false
        (Test-NRProperty $null 'Present') | Should-Be $false
        (Test-NRProperty @{ Present = $null } 'Present') | Should-Be $true
    }

    It 'identifies dictionaries and custom objects but not scalar or sequence values' {
        (Test-NRObjectLike @{ Name = 'value' }) | Should-Be $true
        (Test-NRObjectLike ([pscustomobject]@{ Name = 'value' })) | Should-Be $true
        (Test-NRObjectLike 'value') | Should-Be $false
        (Test-NRObjectLike 12) | Should-Be $false
        (Test-NRObjectLike @('a', 'b')) | Should-Be $false
        (Test-NRObjectLike $null) | Should-Be $false
    }

    It 'normalizes scalar and enumerable Firewall filter values to nullable string arrays' {
        (Get-NRStringArrayFromObject ([pscustomobject]@{ LocalPort = 'Any' }) 'LocalPort') | Should-BeCollection @('Any')
        (Get-NRStringArrayFromObject ([pscustomobject]@{ LocalPort = @('80', '443') }) 'LocalPort') | Should-BeCollection @('80', '443')
        (Get-NRStringArrayFromObject ([pscustomobject]@{ LocalPort = @() }) 'LocalPort') | Should-BeCollection @()
        (Get-NRStringArrayFromObject ([pscustomobject]@{ LocalPort = $null }) 'LocalPort') | Should-Be $null
    }

    It 'converts nested dictionaries and enumerables into JSON-compatible values' {
        $value = Invoke-NRPrivateFunction -Name ConvertTo-NRJsonValue -Parameters @{ Value = @{ z = [System.DayOfWeek]::Monday; a = @('x', 'y') } }
        $json = ConvertTo-Json -InputObject $value -Depth 10 -Compress
        $json | Should-MatchString '"a"'
        $json | Should-MatchString 'Monday'
        (Invoke-NRPrivateFunction -Name ConvertTo-NRJsonValue -Parameters @{ Value = $null }) | Should-Be $null
    }

    It 'retains the order of arrays containing objects while sorting scalar sets' {
        $objects = @([pscustomobject]@{ n = 2 }, [pscustomobject]@{ n = 1 })
        $canonicalObjects = Get-NRCanonicalValue $objects
        (ConvertTo-NRCanonicalJson $canonicalObjects) | Should-MatchString '^\[\{"n":2\},\{"n":1\}\]$'
        (ConvertTo-NRCanonicalJson @('z', 'a')) | Should-Be (ConvertTo-NRCanonicalJson @('a', 'z'))
        (Get-NRPropertyNames $null).Count | Should-Be 0
    }

    It 'reports additions, removals and nested property differences' {
        $before = [pscustomobject]@{ nested = [pscustomobject]@{ old = 'x'; common = 1 }; gone = 2 }
        $after = [pscustomobject]@{ nested = [pscustomobject]@{ added = 'y'; common = 1 }; fresh = 3 }
        $details = @(Get-NRObjectChanges -Before $before -After $after)
        $details.Count | Should-Be 4
        ($details -join "`n") | Should-MatchString 'nested\.added'
        ($details -join "`n") | Should-MatchString 'nested\.old'
        ($details -join "`n") | Should-MatchString 'gone'
        ($details -join "`n") | Should-MatchString 'fresh'
    }

    It 'compares canonical scalar values without JSON conversion when safe' {
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = $null; Right = $null }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = $null; Right = 'value' }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = 'value'; Right = 'value' }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = 'value'; Right = 'Value' }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = $true; Right = $true }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = $true; Right = $false }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = @('a', 'b'); Right = @('b', 'a') }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = 1; Right = '1' }) | Should-Be $false
    }

    It 'keeps PSCustomObject recursive comparisons equivalent for scalar and sequence fast paths' {
        $before = [pscustomobject]@{
            Text = 'case-sensitive'
            Flag = $true
            NullValue = $null
            Tags = @('alpha', 'beta', 'alpha')
            Nested = [pscustomobject]@{
                Ports = @('443', '80')
                NumericValues = [object[]]@(3, 1, 2)
            }
        }
        $after = [pscustomobject]@{
            Nested = [pscustomobject]@{
                NumericValues = [object[]]@(2, 3, 1)
                Ports = @('80', '443')
            }
            Tags = @('alpha', 'alpha', 'beta')
            NullValue = $null
            Flag = $true
            Text = 'case-sensitive'
        }

        @(Get-NRObjectChanges -Before $before -After $after).Count | Should-Be 0

        $after.Text = 'Case-Sensitive'
        $after.Nested.Ports = @('80', '8443')
        $details = @(Get-NRObjectChanges -Before $before -After $after)
        $details.Count | Should-Be 2
        ($details -join "`n") | Should-MatchString 'Nested\.Ports'
        ($details -join "`n") | Should-MatchString 'Text:'
    }

    It 'compares scalar strings and booleans with canonical case and type semantics' {
        $before = [pscustomobject]@{ SameText = 'value'; CaseText = 'value'; SameFlag = $true; ChangedFlag = $true }
        $after = [pscustomobject]@{ SameText = 'value'; CaseText = 'Value'; SameFlag = $true; ChangedFlag = $false }
        $details = @(Get-NRObjectChanges -Before $before -After $after)
        $details.Count | Should-Be 2
        ($details -join "`n") | Should-MatchString 'CaseText'
        ($details -join "`n") | Should-MatchString 'ChangedFlag'
        ($details -join "`n") | Should-NotMatchString 'SameText'
        ($details -join "`n") | Should-NotMatchString 'SameFlag'
    }

    It 'validates key maps and detects empty or duplicate keys' {
        $map = Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{ Items = @([pscustomobject]@{ id = 'a' }); KeyProperty = 'id' }
        $map.ContainsKey('a') | Should-Be $true
        { Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{ Items = @([pscustomobject]@{ id = '' }); KeyProperty = 'id' } } | Should-Throw -ExceptionMessage '*empty*'
        { Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{ Items = @([pscustomobject]@{ id = 'a' }, [pscustomobject]@{ id = 'a' }); KeyProperty = 'id' } } | Should-Throw -ExceptionMessage '*Duplicate*'
    }

    It 'detects nested null transitions only when a current value must be cleared' {
        (Invoke-NRPrivateFunction -Name Test-NRNullTransition -Parameters @{ Current = 10; Desired = $null }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRNullTransition -Parameters @{ Current = $null; Desired = 10 }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRNullTransition -Parameters @{ Current = [pscustomobject]@{ a = 1 }; Desired = [pscustomobject]@{ a = $null } }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRNullTransition -Parameters @{ Current = [pscustomobject]@{ a = 1 }; Desired = [pscustomobject]@{ a = 2 } }) | Should-Be $false
    }
}

Describe 'netrules file I/O and state validation' {
    It 'returns an empty state when the sidecar does not exist' {
        $state = Read-NRStateFile -Path (Join-Path $TestDrive 'missing.state.json')
        $state.schemaVersion | Should-Be 1
        $state.nrptRules.Count | Should-Be 0
    }

    It 'rejects malformed JSON and unsupported sidecar versions' {
        $path = Join-Path $TestDrive 'broken.state.json'
        Set-Content -LiteralPath $path -Value '{not-json'
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*Unable to parse state file*'
        Set-Content -LiteralPath $path -Value '{"schemaVersion":2,"nrptRules":{},"managedFirewallRules":[]}'
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*Invalid state file*'
    }

    It 'rejects duplicate Windows names and invalid logical identifiers in state' {
        $path = Join-Path $TestDrive 'invalid.state.json'
        Set-Content -LiteralPath $path -Value '{"schemaVersion":1,"nrptRules":{"a":"{11111111-1111-1111-1111-111111111111}","b":"{11111111-1111-1111-1111-111111111111}"},"managedFirewallRules":[]}'
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*mapped by multiple logical ids*'
        Set-Content -LiteralPath $path -Value '{"schemaVersion":1,"nrptRules":{"a":""},"managedFirewallRules":[]}'
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*Invalid NRPT state mapping*'
        Set-Content -LiteralPath $path -Value '{"schemaVersion":1,"nrptRules":{"a":123},"managedFirewallRules":[]}'
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*Invalid NRPT state mapping*'
        Set-Content -LiteralPath $path -Value '{"schemaVersion":1,"nrptRules":[],"managedFirewallRules":[]}'
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*Invalid state file*'
    }

    It 'rejects scalar and nested-array managed Firewall inventories' {
        $path = Join-Path $TestDrive 'invalid-managed-inventory.state.json'
        [System.IO.File]::WriteAllText($path, '{"schemaVersion":1,"nrptRules":{},"managedFirewallRules":"Rule-A"}')
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*must be an array of strings*'
        [System.IO.File]::WriteAllText($path, '{"schemaVersion":1,"nrptRules":{},"managedFirewallRules":[["Rule-A"]]}')
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*entries must be scalar strings*'
        [System.IO.File]::WriteAllText($path, '{"schemaVersion":1,"nrptRules":{},"managedFirewallRules":[1]}')
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*entries must be scalar strings*'
    }

    It 'writes BOM-less UTF-8 JSON and creates parent directories' {
        $expectedText = '日本語の設定値'
        $path = Join-Path $TestDrive 'nested\config.json'
        Write-NRJsonFile -Path $path -InputObject ([pscustomobject]@{ schemaVersion = 1; description = $expectedText })
        Test-Path -LiteralPath $path | Should-Be $true
        $bytes = [System.IO.File]::ReadAllBytes($path)
        (($bytes[0] -eq 0xEF) -and ($bytes[1] -eq 0xBB) -and ($bytes[2] -eq 0xBF)) | Should-Be $false
        [System.Text.Encoding]::UTF8.GetString($bytes) | Should-MatchString $expectedText
    }

    It 'writes compact Snapshot JSON and reads it without changing values' {
        $path = Join-Path $TestDrive 'compact.snapshot.json'
        $configuration = New-NRFixtureConfiguration
        $configuration.firewallRules[0].rule.Description = 'Wi-Fi Direct ネットワーク'
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $configuration

        Write-NRJsonFile -Path $path -InputObject $snapshot -Compress
        $json = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
        $json | Should-MatchString '^\{"schemaVersion":1,'
        $actual = Read-NRSnapshot -Path $path
        $actual.configuration.firewallRules[0].rule.Description | Should-Be 'Wi-Fi Direct ネットワーク'
        $actual.comparison.arraySemantics | Should-Be 'Array order is ignored; duplicate elements are retained.'
    }

    It 'round-trips a BOM-less UTF-8 Snapshot containing Japanese text' {
        $expectedText = 'Wi-Fi Direct ネットワーク'
        $path = Join-Path $TestDrive 'utf8-snapshot.json'
        $configuration = New-NRFixtureConfiguration
        $configuration.firewallRules[0].rule.Description = $expectedText
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $configuration

        Write-TestUtf8JsonFile -Path $path -InputObject $snapshot
        $actual = Read-NRSnapshot -Path $path

        $actual.configuration.firewallRules[0].rule.Description | Should-Be $expectedText
        $actual.comparison.stringSemantics | Should-Be 'String values are compared case-sensitively.'
    }

    It 'round-trips a BOM-less UTF-8 Desired Configuration containing Japanese text' {
        $expectedText = '社内ネットワーク'
        $path = Join-Path $TestDrive 'utf8-configuration.json'
        $configuration = [pscustomobject]@{
            schemaVersion = 1
            description = $expectedText
            firewallRules = @()
        }

        Write-TestUtf8JsonFile -Path $path -InputObject $configuration
        $actual = Read-NRConfiguration -Path $path

        $actual.description | Should-Be $expectedText
    }

    It 'round-trips a BOM-less UTF-8 State file containing Japanese names' {
        $expectedNrptName = '社内DNSルール'
        $expectedFirewallName = '社内Firewallルール'
        $path = Join-Path $TestDrive 'utf8-state.json'
        $state = [pscustomobject]@{
            schemaVersion = 1
            nrptRules = [ordered]@{ 'corp-dns' = $expectedNrptName }
            managedFirewallRules = @($expectedFirewallName)
        }

        Write-TestUtf8JsonFile -Path $path -InputObject $state
        $actual = Read-NRStateFile -Path $path

        $actual.nrptRules['corp-dns'] | Should-Be $expectedNrptName
        $actual.managedFirewallRules[0] | Should-Be $expectedFirewallName
        $actual.schemaVersion | Should-Be 1
    }

    It 'writes State sidecars with schema version 1 and the current collections' {
        $path = Join-Path $TestDrive 'written-state.state.json'
        Write-NRStateFile -Path $path -State ([pscustomobject]@{
            nrptRules = @{ 'corp-dns' = 'Windows-NRPT-Name' }
            managedFirewallRules = @('Rule-B', 'Rule-A')
        })
        $written = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $written.schemaVersion | Should-Be 1
        $written.nrptRules.'corp-dns' | Should-Be 'Windows-NRPT-Name'
        @($written.managedFirewallRules) | Should-BeCollection @('Rule-A', 'Rule-B')
    }

    It 'defines v1 JSON Schemas for Snapshot and State sidecars' {
        $schemaRoot = Join-Path $PSScriptRoot '..\schema'
        $snapshotSchemaPath = Join-Path $schemaRoot 'snapshot.schema.json'
        $stateSchemaPath = Join-Path $schemaRoot 'state.schema.json'
        $snapshotSchema = Get-Content -LiteralPath $snapshotSchemaPath -Raw | ConvertFrom-Json
        $stateSchema = Get-Content -LiteralPath $stateSchemaPath -Raw | ConvertFrom-Json

        $snapshotSchema.properties.schemaVersion.const | Should-Be 1
        $snapshotSchema.properties.configuration.'$ref' | Should-Be 'network-rules.schema.json'
        $snapshotDefinitions = $snapshotSchema.PSObject.Properties['$defs'].Value
        $snapshotDefinitions.comparisonField.required | Should-BeCollection @('Value')
        $snapshotDefinitions.comparisonField.additionalProperties | Should-Be $false
        $snapshotDefinitions.comparisonInventory.properties.BulkFilterWarnings.items.'$ref' | Should-Be '#/$defs/filterIssue'
        $stateSchema.properties.schemaVersion.const | Should-Be 1
        $stateSchema.properties.nrptRules.type | Should-Be 'object'
        $stateSchema.properties.managedFirewallRules.type | Should-Be 'array'
        $stateSchema.properties.managedFirewallRules.uniqueItems | Should-Be $true
    }

    It 'rejects missing configuration files and malformed JSON' {
        $missing = Join-Path $TestDrive 'not-found.json'
        { Read-NRConfiguration -Path $missing } | Should-Throw -ExceptionMessage '*not found*'
        Set-Content -LiteralPath $missing -Value '['
        { Read-NRConfiguration -Path $missing } | Should-Throw -ExceptionMessage '*Unable to parse JSON*'
    }
}

Describe 'netrules validation partitions' {
    It 'rejects unsupported root properties and schema versions' {
        $config = New-NRFixtureConfiguration
        Add-Member -InputObject $config -MemberType NoteProperty -Name unsupported -Value $true
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*unsupported property*'
        $config = New-NRFixtureConfiguration
        $config.schemaVersion = 2
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*schemaVersion must be 1*'
    }

    It 'rejects non-array top-level collections' {
        $config = New-NRFixtureConfiguration
        $config.firewallRules = 'not-an-array'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*firewallRules must be an array*'
    }

    It 'accepts legacy configurations without excludedFirewallRules' {
        $config = New-NRFixtureConfiguration
        $config.PSObject.Properties.Remove('excludedFirewallRules')
        Assert-NRConfiguration -Configuration $config | Should-Be $true
    }

    It 'treats a missing or empty exclusion property as an empty list' {
        $legacy = New-NRFixtureConfiguration
        $legacy.PSObject.Properties.Remove('excludedFirewallRules')
        @((Invoke-NRPrivateFunction -Name Get-NRExcludedFirewallRuleNames -Parameters @{ Configuration = $legacy })).Count | Should-Be 0

        $empty = New-NRFixtureConfiguration
        @((Invoke-NRPrivateFunction -Name Get-NRExcludedFirewallRuleNames -Parameters @{ Configuration = $empty })).Count | Should-Be 0
    }

    It 'validates excluded Firewall rule names and prevents managed/excluded overlap' {
        $config = New-NRFixtureConfiguration
        $config.excludedFirewallRules = 'not-an-array'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*excludedFirewallRules must be an array*'

        $config = New-NRFixtureConfiguration
        $config.excludedFirewallRules = @('Rule-A', '')
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*non-empty strings*'

        $config = New-NRFixtureConfiguration
        $config.excludedFirewallRules = @('Rule-A', 42)
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*non-empty strings*'

        $config = New-NRFixtureConfiguration
        $config.excludedFirewallRules = @('Rule-A', 'rule-a')
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*Duplicate excluded Firewall rule name*'

        $config = New-NRFixtureConfiguration
        $config.excludedFirewallRules = @('AllowHttps')
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*cannot be both managed and excluded*'
    }

    It 'validates every Firewall Profile field and rejects unsupported values' {
        $config = New-NRFixtureConfiguration
        $config.firewallProfiles.Private.Enabled = @('True')
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*Enabled must be scalar*'
        $config = New-NRFixtureConfiguration
        $config.firewallProfiles.Public.LogMaxSizeKilobytes = 'large'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*LogMaxSizeKilobytes must be number*'
        $config = New-NRFixtureConfiguration
        Add-Member -InputObject $config.firewallProfiles.Domain -MemberType NoteProperty -Name Unknown -Value 1
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*unsupported property*'
    }

    It 'rejects malformed and duplicate Dynamic Keyword Address definitions' {
        $config = New-NRFixtureConfiguration
        $config.firewallDynamicKeywordAddresses = @([pscustomobject]@{ id = 'not-guid'; Keyword = 'sample'; Addresses = '10.0.0.0/8'; AutoResolve = $false })
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*GUID enclosed in braces*'
        $address = [pscustomobject]@{ id = '{11111111-1111-1111-1111-111111111111}'; Keyword = 'sample'; Addresses = '10.0.0.0/8'; AutoResolve = $false }
        $config.firewallDynamicKeywordAddresses = @($address, (Copy-TestObject $address))
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*Duplicate dynamic keyword address id*'
    }

    It 'requires static addresses and forbids addresses for AutoResolve definitions' {
        $config = New-NRFixtureConfiguration
        $config.firewallDynamicKeywordAddresses = @([pscustomobject]@{ id = '{11111111-1111-1111-1111-111111111111}'; Keyword = 'sample'; Addresses = $null; AutoResolve = $false })
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*must declare Addresses*'
        $config.firewallDynamicKeywordAddresses[0].AutoResolve = $true
        $config.firewallDynamicKeywordAddresses[0].Addresses = '10.0.0.0/8'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*must not declare Addresses*'
    }

    It 'rejects invalid Firewall body and filter types' {
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].rule.LooseSourceMapping = 'false'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*LooseSourceMapping must be boolean*'
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].filters.port.Protocol = 6
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*Protocol must be string*'
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].filters.security.OverrideBlockRules = 'false'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*OverrideBlockRules must be boolean*'
    }

    It 'rejects duplicate NRPT identifiers and invalid NRPT field types' {
        $config = New-NRFixtureConfiguration
        $config.nrptRules += (Copy-TestObject $config.nrptRules[0])
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*Duplicate NRPT id*'
        $config = New-NRFixtureConfiguration
        $config.nrptRules[0].DnsSecEnable = 'false'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*DnsSecEnable must be boolean*'
    }
}

Describe 'netrules capture adapters' {
    It 'serializes static and auto-resolved dynamic keyword addresses' {
        $items = @(
            (New-NRFixtureDynamicKeywordAddress -Properties @{ Id = '{11111111-1111-1111-1111-111111111111}'; Keyword = 'Static'; AutoResolve = $false; Addresses = '10.0.0.0/8' }),
            (New-NRFixtureDynamicKeywordAddress -Properties @{ Id = '{22222222-2222-2222-2222-222222222222}'; Keyword = 'Dynamic'; AutoResolve = $true; Addresses = 'runtime-value' })
        )
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { $items }
        $actual = @(Get-NRFirewallDynamicKeywordAddresses)
        $actual.Count | Should-Be 2
        $actual[0].Addresses | Should-Be '10.0.0.0/8'
        $actual[1].Addresses | Should-Be $null
    }

    It 'rejects a dynamic keyword address without an identifier' {
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @([pscustomobject]@{ Keyword = 'NoId'; AutoResolve = $true }) }
        { Get-NRFirewallDynamicKeywordAddresses } | Should-Throw -ExceptionMessage '*empty Id*'
    }

    It 'captures all three Firewall Profiles from PersistentStore' {
        $items = @()
        foreach ($profileName in @('Domain', 'Private', 'Public')) {
            $item = New-NRFixtureFirewallProfile
            Add-Member -InputObject $item -MemberType NoteProperty -Name Name -Value $profileName
            $items += $item
        }
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { $items }
        $actual = Get-NRFirewallProfiles
        (Get-NRPropertyNames $actual).Count | Should-Be 3
        $actual.Private.LogMaxSizeKilobytes | Should-Be 4096
    }

    It 'fails when a Firewall Profile is missing or duplicated' {
        $items = @([pscustomobject]@{ Name = 'Domain' })
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { $items }
        { Get-NRFirewallProfiles } | Should-Throw -ExceptionMessage '*exactly one PersistentStore firewall profile*'
    }

    It 'projects NRPT Windows properties through the production record adapter' {
        $nativeLikeRule = New-NRFixtureNrptWindowsRule -Properties ([ordered]@{
            IPsecCARestriction = 'CA'
            DirectAccessDnsServers = @('192.0.2.53')
            DirectAccessQueryIPsecEncryption = 'AES'
            DirectAccessProxyName = 'proxy.example'
            DirectAccessProxyType = 'Manual'
            NameServers = @('192.0.2.1')
            DnsSecQueryIPsecEncryption = 'AES'
        })
        $record = Invoke-NRPrivateFunction -Name ConvertTo-NRNrptRecord -Parameters @{
            Rule = $nativeLikeRule; LogicalId = 'unit-nrpt'
        }
        $record.id | Should-Be 'unit-nrpt'
        $record.Namespace | Should-BeCollection @('.unit.example')
        $record.IPsecTrustAuthority | Should-Be 'CA'
        $record.DANameServers | Should-BeCollection @('192.0.2.53')
        $record.NameServers | Should-BeCollection @('192.0.2.1')
        $record.DnsSecEnable | Should-Be $false
        $record.Comment | Should-Be 'fixture'
    }

    It 'projects static and auto-resolved Dynamic Keyword Address objects' {
        $static = Invoke-NRPrivateFunction -Name ConvertTo-NRFirewallDynamicKeywordAddressRecord -Parameters @{
            Address = New-NRFixtureDynamicKeywordAddress -Properties @{ Id = '{22222222-2222-2222-2222-222222222222}'; Keyword = 'Static'; Addresses = '192.0.2.10'; AutoResolve = $false }
        }
        $static.id | Should-Be '{22222222-2222-2222-2222-222222222222}'
        $static.Addresses | Should-Be '192.0.2.10'
        $static.AutoResolve | Should-Be $false

        $autoResolved = Invoke-NRPrivateFunction -Name ConvertTo-NRFirewallDynamicKeywordAddressRecord -Parameters @{
            Address = New-NRFixtureDynamicKeywordAddress -Properties @{ Id = '{33333333-3333-3333-3333-333333333333}'; Keyword = 'Auto'; Addresses = 'ignored'; AutoResolve = $true }
        }
        $autoResolved.Addresses | Should-Be $null
        $autoResolved.AutoResolve | Should-Be $true
    }

    It 'maps local NRPT properties to the declared JSON names and sidecar IDs' {
        $windowsName = '{11111111-1111-1111-1111-111111111111}'
        $item = New-NRFixtureNrptWindowsRule -Properties ([ordered]@{
            Name = $windowsName
            Namespace = @('.corp.example')
            NameServers = @('10.10.0.53')
            DisplayName = 'Corporate DNS'
            Comment = ''
        })
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($item) }
        $actual = @(Get-NRNrptRules -IdByWindowsName @{ $windowsName = 'corp-dns' })
        $actual.Count | Should-Be 1
        $actual[0].id | Should-Be 'corp-dns'
        $actual[0].IPsecTrustAuthority | Should-Be $null
        $actual[0].NameServers[0] | Should-Be '10.10.0.53'
    }

    It 'rejects an NRPT rule with an empty Windows Name' {
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @([pscustomobject]@{ Namespace = @('.example') }) }
        { Get-NRNrptRules } | Should-Throw -ExceptionMessage '*empty Windows Name*'
    }

    It 'returns comparison source alongside configuration when requested by snapshot capture' {
        $path = Join-Path $TestDrive 'capture-source.state.json'
        Write-NRStateFile -Path $path -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        $source = [pscustomobject]@{
            PolicyStore = 'PersistentStore'
            Rules = @([pscustomobject]@{ Name = 'Rule-A'; InstanceID = 'Rule-A' })
            FilterIndexes = @{}
        }
        foreach ($spec in @(Get-NRFirewallFilterSpecs)) { $source.FilterIndexes[$spec.JsonName] = @{} }
        $firewallCapture = [pscustomobject]@{
            Records = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
            ComparisonSource = $source
        }
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { @(
            [pscustomobject]@{ Name = 'Domain' }, [pscustomobject]@{ Name = 'Private' }, [pscustomobject]@{ Name = 'Public' }
        ) }
        Mock Get-NRFirewallDynamicKeywordAddresses -ModuleName PSNetRules { @() }
        Mock Get-NRFirewallRules -ModuleName PSNetRules { $firewallCapture }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @() }
        Mock Write-Progress -ModuleName PSNetRules {}

        $captured = Get-NRCurrentState -StatePath $path -IncludeComparisonSource
        $captured.Configuration.firewallRules.Count | Should-Be 1
        $captured.ComparisonSource.PolicyStore | Should-Be 'PersistentStore'
        $captured.ComparisonSource.Rules.Count | Should-Be 1
        Should-Invoke Get-NRFirewallDynamicKeywordAddresses -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'assembles a current-state snapshot through all capture adapters' {
        $items = @()
        foreach ($profileName in @('Domain', 'Private', 'Public')) {
            $item = New-NRFixtureFirewallProfile
            Add-Member -InputObject $item -MemberType NoteProperty -Name Name -Value $profileName
            $items += $item
        }
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { $items }
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @() }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @() }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @() }
        Mock Write-Progress -ModuleName PSNetRules {}
        $path = Join-Path $TestDrive 'state.json'
        $snapshot = Get-NRCurrentState -StatePath $path
        $snapshot.schemaVersion | Should-Be 1
        $snapshot.firewallRules.Count | Should-Be 0
        $snapshot.nrptRules.Count | Should-Be 0
        $snapshot.firewallProfiles.Private | Should-NotBe $null
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Id -eq 0 -and $Status -like 'Read 3 Firewall Profiles*'
        }
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Id -eq 0 -and $Status -like 'Read 0 Firewall Dynamic Keyword Addresses*'
        }
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Id -eq 0 -and $Status -like 'Read 0 Firewall rules and associated filters*'
        }
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Id -eq 0 -and $Status -like 'Read 0 local NRPT rules*'
        }
    }
}

Describe 'netrules Firewall reconciliation branches' {
    It 'updates a rule by Name in PersistentStore and maps DisplayName to NewDisplayName' {
        $current = New-NRFixtureFirewallRuleRecord
        $desired = Copy-TestObject $current
        $desired.rule.DisplayName = 'Updated HTTPS'
        $desired.filters.port.LocalPort = @('8443')
        Mock Set-NetFirewallRule -ModuleName PSNetRules {}
        Set-NRFirewallRule -Name 'AllowHttps' -Parameters (ConvertTo-NRFirewallParameters $desired)
        Should-Invoke Set-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'AllowHttps' -and $PolicyStore -eq 'PersistentStore' -and
            $NewDisplayName -eq 'Updated HTTPS' -and $LocalPort -contains '8443'
        }
    }

    It 'rejects an empty Firewall rule name before calling Set-NetFirewallRule' {
        Mock Set-NetFirewallRule -ModuleName PSNetRules {}
        { Set-NRFirewallRule -Name ' ' -Parameters @{} } | Should-Throw -ExceptionMessage '*without a Name*'
        Should-Invoke Set-NetFirewallRule -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'recreates an existing rule when a property must be cleared' {
        $current = New-NRFixtureFirewallRuleRecord
        $desired = Copy-TestObject $current
        $desired.rule.Description = $null
        (Test-NRFirewallRuleRequiresRecreation -CurrentRecord $current -DesiredRecord $desired) | Should-Be $true
    }

    It 'recreates a rule when Group, Platform, or Owner changes' {
        foreach ($propertyName in @('Group', 'Platform', 'Owner')) {
            $current = New-NRFixtureFirewallRuleRecord
            $desired = Copy-TestObject $current
            switch ($propertyName) {
                'Group' { $desired.rule.Group = 'new-group' }
                'Platform' { $desired.rule.Platform = @('Windows') }
                'Owner' { $desired.rule.Owner = 'S-1-5-18' }
            }
            (Test-NRFirewallRuleRequiresRecreation -CurrentRecord $current -DesiredRecord $desired) | Should-Be $true
        }
    }

    It 'uses Set for mutable changes and skips unchanged rules' {
        $current = New-NRFixtureFirewallRuleRecord
        $desired = Copy-TestObject $current
        $desired.rule.DisplayName = 'Updated'
        $nativeByName = @{ AllowHttps = [pscustomobject]@{} }
        $snapshotsByName = @{ AllowHttps = $current }
        Mock Set-NetFirewallRule -ModuleName PSNetRules {}
        Mock New-NetFirewallRule -ModuleName PSNetRules {}
        Invoke-NRFirewallRuleReconcile -Name AllowHttps -DesiredRecord $current -CurrentRulesByName $nativeByName -CurrentSnapshotsByName $snapshotsByName
        Invoke-NRFirewallRuleReconcile -Name AllowHttps -DesiredRecord $desired -CurrentRulesByName $nativeByName -CurrentSnapshotsByName $snapshotsByName
        Should-Invoke Set-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke New-NetFirewallRule -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'removes a stale Firewall rule from the local PersistentStore' {
        $native = [pscustomobject]@{ Name = 'AllowHttps' }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @($native) }
        Mock Get-NRFirewallRules -ModuleName PSNetRules { @((New-NRFixtureFirewallRuleRecord)) }
        Mock Remove-NetFirewallRule -ModuleName PSNetRules {}
        Invoke-NRFirewallApply -Desired ([pscustomobject]@{ firewallRules = @() })
        Should-Invoke Remove-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'AllowHttps' -and $PolicyStore -eq 'PersistentStore'
        }
    }

    It 'rejects multiple InterfaceType values that the cmdlet cannot represent' {
        $record = New-NRFixtureFirewallRuleRecord
        $record.filters.interfaceType.InterfaceType = @('Wired', 'Wireless')
        { ConvertTo-NRFirewallParameters -Record $record } | Should-Throw -ExceptionMessage '*Multiple InterfaceType values*'
    }

    It 'maps only non-null Firewall Profile settings' {
        $profileRecord = [pscustomobject]@{ Enabled = $true; LogFileName = $null; LogMaxSizeKilobytes = 1024 }
        $parameters = ConvertTo-NRProfileParameters -Record $profileRecord
        $parameters.Enabled | Should-Be $true
        $parameters.LogMaxSizeKilobytes | Should-Be 1024
        $parameters.ContainsKey('LogFileName') | Should-Be $false
    }

    It 'applies all three Profiles to the PersistentStore' {
        $config = New-NRFixtureConfiguration
        Mock Set-NetFirewallProfile -ModuleName PSNetRules {}
        Invoke-NRFirewallProfileApply -Desired $config
        Should-Invoke Set-NetFirewallProfile -ModuleName PSNetRules -Times 3 -Exactly
    }
}

Describe 'netrules dynamic keyword reconciliation branches' {
    It 'updates static addresses without recreating an unchanged keyword' {
        $id = '{11111111-1111-1111-1111-111111111111}'
        $current = [pscustomobject]@{ Id = $id; Keyword = 'Static'; AutoResolve = $false; Addresses = '10.0.0.0/8' }
        $desired = [pscustomobject]@{ id = $id; Keyword = 'Static'; AutoResolve = $false; Addresses = '10.1.0.0/16' }
        Mock Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Mock New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Mock Update-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Update-NRFirewallDynamicKeyword -CurrentRecord $current -DesiredRecord $desired -Id $id
        Should-Invoke Update-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Id -eq $id -and $Addresses -eq '10.1.0.0/16' -and $Append -eq $false }
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'recreates a keyword when its Keyword or AutoResolve value changes' {
        $id = '{11111111-1111-1111-1111-111111111111}'
        $current = [pscustomobject]@{ Id = $id; Keyword = 'Old'; AutoResolve = $false; Addresses = '10.0.0.0/8' }
        $desired = [pscustomobject]@{ id = $id; Keyword = 'New'; AutoResolve = $false; Addresses = '10.1.0.0/16' }
        Mock Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Mock New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Update-NRFirewallDynamicKeyword -CurrentRecord $current -DesiredRecord $desired -Id $id
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'removes stale dynamic keyword addresses only when RemoveStale is specified' {
        $id = '{11111111-1111-1111-1111-111111111111}'
        $current = [pscustomobject]@{ Id = $id; Keyword = 'Static'; AutoResolve = $false; Addresses = '10.0.0.0/8' }
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @($current) }
        Mock Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        $emptyDesired = [pscustomobject]@{ firewallDynamicKeywordAddresses = @() }
        Invoke-NRFirewallDynamicKeywordApply -Desired $emptyDesired
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 0 -Exactly
        Invoke-NRFirewallDynamicKeywordApply -Desired $emptyDesired -RemoveStale
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'removes only Firewall rules that reference a recreated keyword' {
        $id = '{11111111-1111-1111-1111-111111111111}'
        $oldAddress = [pscustomobject]@{ id = $id; Keyword = 'Old'; AutoResolve = $false; Addresses = '10.0.0.0/8' }
        $newAddress = [pscustomobject]@{ id = $id; Keyword = 'New'; AutoResolve = $false; Addresses = '10.0.0.0/8' }
        $used = New-NRFixtureFirewallRuleRecord -Name 'UsesKeyword'
        $used.rule.RemoteDynamicKeywordAddresses = @($id)
        $unused = New-NRFixtureFirewallRuleRecord -Name 'DoesNotUseKeyword'
        $current = [pscustomobject]@{ firewallDynamicKeywordAddresses = @($oldAddress); firewallRules = @($used, $unused) }
        $desired = [pscustomobject]@{ firewallDynamicKeywordAddresses = @($newAddress); firewallRules = @($used, $unused) }
        Mock Remove-NetFirewallRule -ModuleName PSNetRules {}
        Remove-NRRulesReferencingRecreatedDynamicKeywords -Desired $desired -Current $current
        Should-Invoke Remove-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Name -eq 'UsesKeyword' }
    }
}

Describe 'netrules NRPT reconciliation branches' {
    It 'builds an index from Windows names and sidecar mappings' {
        $nativeRule = [pscustomobject]@{ Name = '{11111111-1111-1111-1111-111111111111}' }
        $index = Get-NRNrptCurrentIndex -Rules @($nativeRule) -StateMap @{ 'corp-dns' = $nativeRule.Name }
        $index.CurrentById.ContainsKey('corp-dns') | Should-Be $true
        $index.NameById['corp-dns'] | Should-Be $nativeRule.Name
    }

    It 'rejects collisions where two rules map to the same logical identifier' {
        $guid = '{11111111-1111-1111-1111-111111111111}'
        $nativeRules = @([pscustomobject]@{ Name = $guid }, [pscustomobject]@{ Name = '{22222222-2222-2222-2222-222222222222}' })
        $stateMap = @{ 'logical-id' = $guid; '{22222222-2222-2222-2222-222222222222}' = $guid }
        { Get-NRNrptCurrentIndex -Rules $nativeRules -StateMap $stateMap } | Should-Throw -ExceptionMessage '*multiple logical ids*'
    }

    It 'does not recreate an unchanged NRPT rule and persists its existing GUID' {
        $windowsName = '{33333333-3333-3333-3333-333333333333}'
        $desiredRecord = New-NRFixtureNrptRuleRecord
        $native = New-NRFixtureNrptWindowsRule -Properties ([ordered]@{
            Name = $windowsName
            Namespace = $desiredRecord.Namespace
            NameServers = $desiredRecord.NameServers
            DisplayName = 'Corporate DNS'
            Comment = ''
        })
        $stateMap = @{ 'corp-dns' = $windowsName }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($native) }
        Mock Add-DnsClientNrptRule -ModuleName PSNetRules { throw 'Should not add an unchanged NRPT rule.' }
        Mock Remove-DnsClientNrptRule -ModuleName PSNetRules { throw 'Should not remove an unchanged NRPT rule.' }
        $statePath = Join-Path $TestDrive 'unchanged.state.json'
        Invoke-NRNrptApply -Desired ([pscustomobject]@{ nrptRules = @($desiredRecord) }) -StateMap $stateMap -StatePath $statePath
        Should-Invoke Add-DnsClientNrptRule -ModuleName PSNetRules -Times 0 -Exactly
        Should-Invoke Remove-DnsClientNrptRule -ModuleName PSNetRules -Times 0 -Exactly
        (Read-NRStateFile -Path $statePath).nrptRules['corp-dns'] | Should-Be $windowsName
    }

    It 'removes stale NRPT rules and updates the sidecar' {
        $windowsName = '{44444444-4444-4444-4444-444444444444}'
        $currentById = @{ old = [pscustomobject]@{ Name = $windowsName } }
        $nameById = @{ old = $windowsName }
        $stateMap = @{ old = $windowsName }
        Mock Remove-DnsClientNrptRule -ModuleName PSNetRules {}
        $statePath = Join-Path $TestDrive 'stale.state.json'
        Remove-NRStaleNrptRules -CurrentById $currentById -NameById $nameById -DesiredRules @{} -StateMap $stateMap -StatePath $statePath
        Should-Invoke Remove-DnsClientNrptRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Name -eq $windowsName -and $Force }
        $currentById.Count | Should-Be 0
        (Read-NRStateFile -Path $statePath).nrptRules.Count | Should-Be 0
    }

    It 'fails if Add-DnsClientNrptRule does not return a generated Windows Name' {
        Mock Add-DnsClientNrptRule -ModuleName PSNetRules { [pscustomobject]@{ Namespace = @('.corp.example') } }
        $statePath = Join-Path $TestDrive 'bad-add.state.json'
        { Add-NRNrptRuleAndTrack -LogicalId 'corp-dns' -Record (New-NRFixtureNrptRuleRecord) -StateMap @{} -StatePath $statePath } |
            Should-Throw -ExceptionMessage '*did not return the generated Windows Name*'
    }
}

Describe 'netrules public command workflows' {
    It 'validates a configuration file through Invoke-NRValidate' {
        $path = Join-Path $TestDrive 'valid.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        $output = Invoke-NRValidate -Path $path
        $output | Should-Be 'Configuration is valid.'
    }

    It 'initializes an empty Firewall desired state while retaining all rules in the capture snapshot' {
        $path = Join-Path $TestDrive 'capture.json'
        $captured = New-NRFixtureConfiguration
        Mock Assert-NRAdministrator -ModuleName PSNetRules {}
        Mock New-NRCaptureSnapshot -ModuleName PSNetRules { New-NRFixtureCaptureSnapshot -Configuration $captured }
        Mock Write-Progress -ModuleName PSNetRules {}

        $output = Invoke-NRCapture -Path $path
        (@($output) -join [Environment]::NewLine) | Should-MatchString 'Captured snapshot:'
        $desired = Read-NRConfiguration -Path $path
        $desired.firewallRules.Count | Should-Be 0
        $desired.nrptRules.Count | Should-Be 1
        $snapshot = Read-NRSnapshot -Path (Get-NRSnapshotPath -Path $path)
        $snapshot.configuration.firewallRules.Count | Should-Be 1
        (Read-NRStateFile -Path (Get-NRStatePath -Path $path)).managedFirewallRules.Count | Should-Be 0
    }

    It 'refreshes an existing snapshot without overwriting the desired configuration' {
        $path = Join-Path $TestDrive 'capture-refresh.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $captured = New-NRFixtureConfiguration
        Mock Assert-NRAdministrator -ModuleName PSNetRules {}
        Mock New-NRCaptureSnapshot -ModuleName PSNetRules { New-NRFixtureCaptureSnapshot -Configuration $captured }
        Mock Write-Progress -ModuleName PSNetRules {}

        $captureOutput = @(Invoke-NRCapture -Path $path) -join [Environment]::NewLine
        $captureOutput | Should-MatchString 'Captured snapshot:'
        (Read-NRConfiguration -Path $path).firewallRules.Count | Should-Be 0
        (Read-NRSnapshot -Path (Get-NRSnapshotPath -Path $path)).configuration.firewallRules.Count | Should-Be 1
    }

}

Describe 'netrules JSON and normalization helpers' {
    It 'computes the sidecar path next to the management JSON' {
        (Get-NRStatePath -Path (Join-Path $TestDrive 'network-rules.json')) | Should-Be (Join-Path $TestDrive 'network-rules.state.json')
    }

    It 'captures relative paths from the PowerShell location instead of the .NET process directory' {
        $powerShellLocation = Join-Path $TestDrive 'powershell-location'
        $dotNetLocation = Join-Path $TestDrive 'dotnet-location'
        New-Item -ItemType Directory -Path $powerShellLocation, $dotNetLocation -Force | Out-Null
        $originalLocation = Get-Location
        $originalDotNetDirectory = [Environment]::CurrentDirectory
        try {
            Set-Location -LiteralPath $powerShellLocation
            [Environment]::CurrentDirectory = $dotNetLocation

            (Get-NRStatePath -Path '.\network-rules.json') |
                Should-Be (Join-Path $powerShellLocation 'network-rules.state.json')

            $captured = New-NRFixtureConfiguration
            Mock Assert-NRAdministrator -ModuleName PSNetRules {}
            Mock New-NRCaptureSnapshot -ModuleName PSNetRules { New-NRFixtureCaptureSnapshot -Configuration $captured }
            Mock Write-Progress -ModuleName PSNetRules {}
            $captureOutput = @(Invoke-NRCapture -Path '.\captured.json') -join [Environment]::NewLine
            $captureOutput | Should-MatchString 'Captured snapshot:'

            (Test-Path -LiteralPath (Join-Path $powerShellLocation 'captured.json')) | Should-Be $true
            (Test-Path -LiteralPath (Join-Path $dotNetLocation 'captured.json')) | Should-Be $false
        }
        finally {
            [Environment]::CurrentDirectory = $originalDotNetDirectory
            Set-Location -LiteralPath $originalLocation.Path
        }
    }

    It 'normalizes object-key order and unordered scalar arrays' {
        $left = [pscustomobject]@{ z = 1; items = @('b', 'a'); nested = [pscustomobject]@{ y = 2; x = 1 } }
        $right = [pscustomobject]@{ nested = [pscustomobject]@{ x = 1; y = 2 }; items = @('a', 'b'); z = 1 }
        (ConvertTo-NRCanonicalJson $left) | Should-Be (ConvertTo-NRCanonicalJson $right)
    }

    It 'round-trips the NRPT identifier map' {
        $path = Join-Path $TestDrive 'network-rules.state.json'
        $state = [pscustomobject]@{ nrptRules = @{ 'corp-dns' = '{11111111-1111-1111-1111-111111111111}' }; managedFirewallRules = @() }
        Write-NRStateFile -Path $path -State $state
        $actual = Read-NRStateFile -Path $path
        $actual.nrptRules['corp-dns'] | Should-Be '{11111111-1111-1111-1111-111111111111}'
    }

    It 'validates a complete configuration object' {
        $config = New-NRFixtureConfiguration
        Assert-NRConfiguration -Configuration $config | Should-Be $true
    }

    It 'rejects duplicate firewall rule names' {
        $config = New-NRFixtureConfiguration
        $config.firewallRules = @((New-NRFixtureFirewallRuleRecord), (New-NRFixtureFirewallRuleRecord))
        { Assert-NRConfiguration -Configuration $config } | Should-Throw
    }

    It 'rejects a mismatched outer and inner firewall rule name' {
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].rule.name = 'different-name'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*mismatched*'
    }

    It 'rejects unsupported properties instead of silently ignoring them' {
        $config = New-NRFixtureConfiguration
        Add-Member -InputObject $config.firewallRules[0].filters.port -MemberType NoteProperty -Name Unexpected -Value 'value'
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*unsupported property*'
    }

    It 'rejects a Firewall rule referencing an undeclared dynamic keyword address' {
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].rule.RemoteDynamicKeywordAddresses = @('{11111111-1111-1111-1111-111111111111}')
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*undeclared dynamic keyword address*'
    }

    It 'rejects an NRPT rule without a namespace' {
        $config = New-NRFixtureConfiguration
        $config.nrptRules[0].Namespace = @()
        { Assert-NRConfiguration -Configuration $config } | Should-Throw -ExceptionMessage '*Namespace*'
    }
}

Describe 'netrules desired-state diff' {
    It 'reports adds, updates, and deletes for firewall and NRPT rules' {
        $desired = New-NRFixtureConfiguration -Port '8443'
        $desired.firewallRules += (New-NRFixtureFirewallRuleRecord -Name 'AllowNew' -LocalPort '9000')
        $desired.nrptRules += (New-NRFixtureNrptRuleRecord -Id 'new-dns' -Server '10.10.0.54')

        $current = New-NRFixtureConfiguration -Port '443'
        $current.firewallRules += (New-NRFixtureFirewallRuleRecord -Name 'RemoveMe' -LocalPort '1234')
        $current.nrptRules += (New-NRFixtureNrptRuleRecord -Id 'remove-dns' -Server '10.10.0.55')

        $changes = @(Get-NRDiff -Desired $desired -Current $current)
        (@($changes | Where-Object { $_.Target -eq 'FirewallRule' -and $_.Action -eq 'Update' }).Count) | Should-Be 1
        (@($changes | Where-Object { $_.Target -eq 'FirewallRule' -and $_.Action -eq 'Add' }).Count) | Should-Be 1
        (@($changes | Where-Object { $_.Target -eq 'FirewallRule' -and $_.Action -eq 'Delete' }).Count) | Should-Be 1
        (@($changes | Where-Object { $_.Target -eq 'NrptRule' -and $_.Action -eq 'Add' }).Count) | Should-Be 1
        (@($changes | Where-Object { $_.Target -eq 'NrptRule' -and $_.Action -eq 'Delete' }).Count) | Should-Be 1
        (@($changes | Where-Object { $_.Target -eq 'NrptRule' -and $_.Action -eq 'Update' }).Count) | Should-Be 0
    }

    It 'can skip Firewall Rule comparisons while retaining other resource diffs' {
        $desired = New-NRFixtureConfiguration -Port '8443'
        $desired.firewallProfiles.Private.Enabled = 'False'
        $desired.nrptRules = @((New-NRFixtureNrptRuleRecord -Id 'desired-dns' -Server '10.10.0.54'))
        $current = New-NRFixtureConfiguration -Port '443'
        $current.nrptRules = @((New-NRFixtureNrptRuleRecord -Id 'current-dns' -Server '10.10.0.55'))

        $changes = @(Get-NRDiff -Desired $desired -Current $current -SkipFirewallRules)
        @($changes | Where-Object { $_.Target -eq 'FirewallRule' }).Count | Should-Be 0
        @($changes | Where-Object { $_.Target -eq 'NrptRule' -and $_.Action -eq 'Add' }).Count | Should-Be 1
        @($changes | Where-Object { $_.Target -eq 'NrptRule' -and $_.Action -eq 'Delete' }).Count | Should-Be 1
        @($changes | Where-Object { $_.Target -eq 'FirewallProfile' -and $_.Key -eq 'Private' }).Count | Should-Be 1
    }

    It 'reports dynamic keyword address additions and removals' {
        $desired = New-NRFixtureConfiguration
        $current = New-NRFixtureConfiguration
        $desired.firewallDynamicKeywordAddresses = @([pscustomobject]@{ id = '{11111111-1111-1111-1111-111111111111}'; Keyword = 'api.example.com'; Addresses = $null; AutoResolve = $true })
        $current.firewallDynamicKeywordAddresses = @([pscustomobject]@{ id = '{22222222-2222-2222-2222-222222222222}'; Keyword = 'old.example.com'; Addresses = '10.0.0.1'; AutoResolve = $false })
        $changes = @(Get-NRDiff -Desired $desired -Current $current)
        @($changes | Where-Object { $_.Target -eq 'FirewallDynamicKeywordAddress' -and $_.Action -eq 'Add' }).Count | Should-Be 1
        @($changes | Where-Object { $_.Target -eq 'FirewallDynamicKeywordAddress' -and $_.Action -eq 'Delete' }).Count | Should-Be 1
    }

    It 'reports an update when a Firewall Profile property differs' {
        $desired = New-NRFixtureConfiguration
        $current = New-NRFixtureConfiguration
        $desired.firewallProfiles.Private.DefaultInboundAction = 'Allow'
        $changes = @(Get-NRDiff -Desired $desired -Current $current)
        $profileChanges = @($changes | Where-Object { $_.Target -eq 'FirewallProfile' -and $_.Key -eq 'Private' })
        $profileChanges.Count | Should-Be 1
        $profileChanges[0].Details[0] | Should-MatchString 'DefaultInboundAction'
    }

    It 'does not report changes when array order alone differs' {
        $desired = New-NRFixtureConfiguration
        $current = New-NRFixtureConfiguration
        $desired.firewallRules[0].filters.address.RemoteAddress = @('10.0.0.2', '10.0.0.1')
        $current.firewallRules[0].filters.address.RemoteAddress = @('10.0.0.1', '10.0.0.2')
        @(Get-NRDiff -Desired $desired -Current $current).Count | Should-Be 0
    }

    It 'handles empty desired-state collections without creating phantom items' {
        $desired = New-NRFixtureConfiguration
        $current = New-NRFixtureConfiguration
        foreach ($configuration in @($desired, $current)) {
            $configuration.firewallDynamicKeywordAddresses = @()
            $configuration.firewallRules = @()
            $configuration.nrptRules = @()
        }

        @(Get-NRDiff -Desired $desired -Current $current).Count | Should-Be 0
    }
}

Describe 'netrules command parameter mapping' {
    It 'flattens firewall properties and associated filters for New/Set-NetFirewallRule' {
        $rule = New-NRFixtureFirewallRuleRecord -LocalPort '9443'
        $parameters = ConvertTo-NRFirewallParameters -Record $rule
        $parameters['DisplayName'] | Should-Be 'AllowHttps'
        $parameters['Protocol'] | Should-Be 'TCP'
        $parameters['LocalPort'][0] | Should-Be '9443'
        $parameters['RemoteAddress'][0] | Should-Be 'Any'
        $parameters['Authentication'] | Should-Be 'NotRequired'
    }

    It 'maps NRPT properties and only sends true switches on rule creation' {
        $rule = New-NRFixtureNrptRuleRecord
        $rule.DnsSecEnable = $true
        $rule.DAEnable = $false
        $parameters = ConvertTo-NRNrptParameters -Record $rule -ForAdd
        $parameters['Namespace'][0] | Should-Be '.corp.example'
        $parameters['NameServers'][0] | Should-Be '10.10.0.53'
        $parameters.ContainsKey('DnsSecEnable') | Should-Be $true
        $parameters.ContainsKey('DAEnable') | Should-Be $false
    }

    It 'removes the logical id before comparing NRPT values with Windows properties' {
        $record = New-NRFixtureNrptRuleRecord
        $comparable = ConvertTo-NRNrptDesiredComparable $record
        (Get-NRPropertyNames $comparable) -contains 'id' | Should-Be $false
    }
}

Describe 'netrules backup files' {
    It 'writes a pre-apply snapshot and a matching state sidecar' {
        $configPath = Join-Path $TestDrive 'network-rules.json'
        $state = [pscustomobject]@{ nrptRules = @{ 'corp-dns' = '{22222222-2222-2222-2222-222222222222}' }; managedFirewallRules = @() }
        $current = New-NRFixtureConfiguration
        $backup = New-NRBackup -ConfigurationPath $configPath -CurrentState $current -State $state
        Test-Path -LiteralPath $backup | Should-Be $true
        Test-Path -LiteralPath ($backup -replace '\.json$', '.state.json') | Should-Be $true
        $saved = Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
        $saved.schemaVersion | Should-Be 1
    }
}


Describe 'netrules Windows cmdlet boundary' {
    It 'returns an empty collection when PersistentStore has no Firewall rules' {
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @() }
        @(Get-NRFirewallRules).Count | Should-Be 0
    }

    It 'captures every Firewall filter type using one bulk query per type and normalizes scalar ports to arrays' {
        $ruleId = 'TestFirewallRule'
        $rule = [pscustomobject]@{ Name = $ruleId }
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules { [pscustomobject]@{ InstanceID = $ruleId; LocalAddress = 'Any'; RemoteAddress = @('10.0.0.0/8') } }
        Mock Get-NetFirewallPortFilter -ModuleName PSNetRules { [pscustomobject]@{ InstanceID = $ruleId; Protocol = 'TCP'; LocalPort = '443'; RemotePort = @('Any'); IcmpType = $null; DynamicTarget = 'Any' } }
        Mock Get-NetFirewallApplicationFilter -ModuleName PSNetRules { [pscustomobject]@{ InstanceID = $ruleId; Program = 'Any'; Package = 'Any' } }
        Mock Get-NetFirewallServiceFilter -ModuleName PSNetRules { [pscustomobject]@{ InstanceID = $ruleId; Service = 'Any' } }
        Mock Get-NetFirewallInterfaceFilter -ModuleName PSNetRules { [pscustomobject]@{ InstanceID = $ruleId; InterfaceAlias = 'Any' } }
        Mock Get-NetFirewallInterfaceTypeFilter -ModuleName PSNetRules { [pscustomobject]@{ InstanceID = $ruleId; InterfaceType = @('Any') } }
        Mock Get-NetFirewallSecurityFilter -ModuleName PSNetRules { [pscustomobject]@{ InstanceID = $ruleId; LocalUser = 'Any'; RemoteUser = 'Any'; RemoteMachine = 'Any'; Authentication = 'NotRequired'; Encryption = 'NotRequired'; OverrideBlockRules = $false } }

        $filters = Get-NRFirewallFilter -Rule $rule

        $filters.address.RemoteAddress[0] | Should-Be '10.0.0.0/8'
        $filters.address.LocalAddress | Should-BeCollection @('Any')
        $filters.port.LocalPort | Should-BeCollection @('443')
        $filters.port.IcmpType | Should-Be $null
        $filters.application.Program | Should-Be 'Any'
        $filters.service.Service | Should-Be 'Any'
        $filters.interface.InterfaceAlias | Should-BeCollection @('Any')
        $filters.interfaceType.InterfaceType[0] | Should-Be 'Any'
        $filters.security.Authentication | Should-Be 'NotRequired'
        foreach ($cmdlet in @(
            'Get-NetFirewallAddressFilter', 'Get-NetFirewallPortFilter', 'Get-NetFirewallApplicationFilter',
            'Get-NetFirewallServiceFilter', 'Get-NetFirewallInterfaceFilter',
            'Get-NetFirewallInterfaceTypeFilter', 'Get-NetFirewallSecurityFilter'
        )) {
            Should-Invoke $cmdlet -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
                $All -and $PolicyStore -eq 'PersistentStore'
            }
        }
    }

    It 'creates a declared Firewall rule in PersistentStore' {
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @() }
        Mock New-NetFirewallRule -ModuleName PSNetRules {}
        $desired = [pscustomobject]@{ firewallRules = @((New-NRFixtureFirewallRuleRecord)) }

        Invoke-NRFirewallApply -Desired $desired

        Should-Invoke New-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'AllowHttps' -and $PolicyStore -eq 'PersistentStore' -and $LocalPort -contains '443'
        }
    }

    It 'adds an NRPT rule and persists the generated Windows GUID' {
        $windowsName = '{33333333-3333-3333-3333-333333333333}'
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @() }
        Mock Add-DnsClientNrptRule -ModuleName PSNetRules { [pscustomobject]@{ Name = '{33333333-3333-3333-3333-333333333333}' } }
        $statePath = Join-Path $TestDrive 'network-rules.state.json'
        $desired = [pscustomobject]@{ nrptRules = @((New-NRFixtureNrptRuleRecord)) }
        $stateMap = @{}

        Invoke-NRNrptApply -Desired $desired -StateMap $stateMap -StatePath $statePath

        $state = Read-NRStateFile -Path $statePath
        $state.nrptRules['corp-dns'] | Should-Be $windowsName
        Should-Invoke Add-DnsClientNrptRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $PassThru -and $Namespace -contains '.corp.example'
        }
    }

    It 'recreates a changed NRPT rule so omitted properties are reset' {
        $windowsName = '{44444444-4444-4444-4444-444444444444}'
        $newWindowsName = '{55555555-5555-5555-5555-555555555555}'
        $existing = [pscustomobject]@{
            Name = $windowsName
            Namespace = @('.corp.example')
            IPsecCARestriction = $null
            DirectAccessDnsServers = @()
            DirectAccessEnabled = $false
            DirectAccessQueryIPsecEncryption = $null
            DirectAccessQueryIPsecRequired = $false
            DirectAccessProxyName = $null
            DirectAccessProxyType = $null
            NameServers = @('10.10.0.53')
            NameEncoding = 'Punycode'
            DnsSecEnabled = $false
            DnsSecQueryIPsecEncryption = $null
            DnsSecQueryIPsecRequired = $false
            DnsSecValidationRequired = $false
            DisplayName = 'Old name'
            Comment = ''
        }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($existing) }
        Mock Remove-DnsClientNrptRule -ModuleName PSNetRules {}
        Mock Add-DnsClientNrptRule -ModuleName PSNetRules { [pscustomobject]@{ Name = $newWindowsName } }
        Mock Set-DnsClientNrptRule -ModuleName PSNetRules {}
        $statePath = Join-Path $TestDrive 'network-rules.state.json'
        $desired = [pscustomobject]@{ nrptRules = @((New-NRFixtureNrptRuleRecord)) }
        $stateMap = @{ 'corp-dns' = $windowsName }

        Invoke-NRNrptApply -Desired $desired -StateMap $stateMap -StatePath $statePath

        Should-Invoke Remove-DnsClientNrptRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Name -eq $windowsName -and $Force }
        Should-Invoke Add-DnsClientNrptRule -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Set-DnsClientNrptRule -ModuleName PSNetRules -Times 0 -Exactly
        (Read-NRStateFile -Path $statePath).nrptRules['corp-dns'] | Should-Be $newWindowsName
    }
}


Describe 'netrules dynamic keyword addresses' {
    It 'creates a static dynamic keyword address with its declared GUID' {
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @() }
        Mock New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        $desired = [pscustomobject]@{
            firewallDynamicKeywordAddresses = @([pscustomobject]@{
                id = '{11111111-1111-1111-1111-111111111111}'
                Keyword = 'DevSubnet'
                Addresses = '10.10.0.0/16'
                AutoResolve = $false
            })
        }

        Invoke-NRFirewallDynamicKeywordApply -Desired $desired

        Should-Invoke New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Id -eq '{11111111-1111-1111-1111-111111111111}' -and $Keyword -eq 'DevSubnet' -and $Addresses -eq '10.10.0.0/16' -and $AutoResolve -eq $false
        }
    }
}

Describe 'netrules additional branch coverage' {
    It 'validates each supported JSON field type' {
        (Test-NRNumberValue 1) | Should-Be $true
        (Test-NRNumberValue 1.5) | Should-Be $true
        (Test-NRNumberValue '1') | Should-Be $false
        (Test-NRScalarValue ([System.DayOfWeek]::Monday)) | Should-Be $true
        (Test-NRScalarValue ([pscustomobject]@{ x = 1 })) | Should-Be $false
        (Test-NRStringArrayValue -Value ([string[]]@())) | Should-Be $true
        (Test-NRStringArrayValue @('a', 'b')) | Should-Be $true
        (Test-NRStringArrayValue @('a', 2)) | Should-Be $false
        (Test-NRStringArrayValue 'a') | Should-Be $false
        (Test-NRStringOrArrayValue 'a') | Should-Be $true
        (Test-NRStringOrArrayValue @('a')) | Should-Be $true
        (Test-NRFieldValue -Value $true -Kind boolean) | Should-Be $true
        (Test-NRFieldValue -Value 'x' -Kind unsupported) | Should-Be $false
        { Assert-NRFieldType -Object @{ field = 1 } -Field field -Kind string -Context test } |
            Should-Throw -ExceptionMessage '*must be string*'
        Assert-NRFieldType -Object @{ field = $null } -Field field -Kind string -Context test
    }

    It 'validates PSCustomObject shapes through the direct property path' {
        $valid = [pscustomobject]@{ Required = $null; Optional = 1 }
        Assert-NRObjectShape -Object $valid -RequiredFields @('required') -AllowedFields @('required', 'optional') -Context sample

        $missing = [pscustomobject]@{ other = 1 }
        { Assert-NRObjectShape -Object $missing -RequiredFields @('required') -AllowedFields @('required', 'other') -Context sample } |
            Should-Throw -ExceptionMessage '*sample.required is required*'

        $unsupported = [pscustomobject]@{ required = 1; extra = 2 }
        { Assert-NRObjectShape -Object $unsupported -RequiredFields @('required') -AllowedFields @('required') -Context sample } |
            Should-Throw -ExceptionMessage '*unsupported property*'
    }

    It 'validates PSCustomObject field types through the direct property path' {
        $valid = [pscustomobject]@{
            Text = 'value'
            Flag = $true
            Number = [uint64]42
            Scalar = [System.DayOfWeek]::Monday
            Strings = @('one', 'two')
            StringOrArray = 'one'
            EmptyStrings = @()
            Nullable = $null
        }
        Assert-NRFieldType -Object $valid -Field Text -Kind string -Context sample
        Assert-NRFieldType -Object $valid -Field Flag -Kind boolean -Context sample
        Assert-NRFieldType -Object $valid -Field Number -Kind number -Context sample
        Assert-NRFieldType -Object $valid -Field Scalar -Kind scalar -Context sample
        Assert-NRFieldType -Object $valid -Field Strings -Kind stringArray -Context sample
        Assert-NRFieldType -Object $valid -Field StringOrArray -Kind stringOrArray -Context sample
        Assert-NRFieldType -Object $valid -Field EmptyStrings -Kind stringArray -Context sample
        Assert-NRFieldType -Object $valid -Field Nullable -Kind string -Context sample

        { Assert-NRFieldType -Object ([pscustomobject]@{ Strings = @('one', 2) }) -Field Strings -Kind stringArray -Context sample } |
            Should-Throw -ExceptionMessage '*sample.Strings must be stringArray or null*'
        { Assert-NRFieldType -Object ([pscustomobject]@{ Number = '42' }) -Field Number -Kind number -Context sample } |
            Should-Throw -ExceptionMessage '*sample.Number must be number or null*'
    }

    It 'rejects null objects, missing fields and unsupported object shape properties' {
        { Assert-NRObjectShape -Object $null -RequiredFields @('x') -AllowedFields @('x') -Context sample } |
            Should-Throw -ExceptionMessage '*required and must be an object*'
        { Assert-NRObjectShape -Object @{} -RequiredFields @('x') -AllowedFields @('x') -Context sample } |
            Should-Throw -ExceptionMessage '*sample.x is required*'
        { Assert-NRObjectShape -Object @{ x = 1; y = 2 } -RequiredFields @('x') -AllowedFields @('x') -Context sample } |
            Should-Throw -ExceptionMessage '*unsupported property*'
    }

    It 'rejects invalid root schema version and every non-array collection' {
        $config = New-NRFixtureConfiguration
        $config.schemaVersion = 2
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*schemaVersion must be 1*'
        foreach ($field in @('firewallDynamicKeywordAddresses', 'firewallRules', 'nrptRules')) {
            $config = New-NRFixtureConfiguration
            $config.$field = 'not-an-array'
            { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage "*$field must be an array*"
        }
    }

    It 'rejects each malformed dynamic keyword address condition' {
        $base = [pscustomobject]@{ id = '{11111111-1111-1111-1111-111111111111}'; Keyword = 'KW'; Addresses = '10.0.0.0/8'; AutoResolve = $false }
        $known = @{}
        Assert-NRDynamicKeywordAddress -Address $base -KnownIds $known
        { Assert-NRDynamicKeywordAddress -Address $base -KnownIds $known } | Should-Throw -ExceptionMessage '*Duplicate*'
        $bad = Copy-TestObject $base; $bad.id = 'not-guid'
        { Assert-NRDynamicKeywordAddress -Address $bad -KnownIds @{} } | Should-Throw -ExceptionMessage '*must be a GUID*'
        $bad = Copy-TestObject $base; $bad.Keyword = ''
        { Assert-NRDynamicKeywordAddress -Address $bad -KnownIds @{} } | Should-Throw -ExceptionMessage '*must have a Keyword*'
        $bad = Copy-TestObject $base; $bad.AutoResolve = $true
        { Assert-NRDynamicKeywordAddress -Address $bad -KnownIds @{} } | Should-Throw -ExceptionMessage '*must not declare Addresses*'
        $bad = Copy-TestObject $base; $bad.Addresses = ''
        { Assert-NRDynamicKeywordAddress -Address $bad -KnownIds @{} } | Should-Throw -ExceptionMessage '*must declare Addresses*'
    }

    It 'validates firewall rule references and rejects malformed filters' {
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].name = ''
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*non-empty name*'
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].rule.Enabled = @('yes')
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*must be scalar*'
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].filters.port.Protocol = @('TCP')
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*must be string*'
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].filters.interface.InterfaceAlias = @('Ethernet', 5)
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*must be stringArray*'
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].filters.interfaceType.InterfaceType = @('Wired', 'Wireless')
        (Assert-NRConfiguration $config) | Should-Be $true
        { ConvertTo-NRFirewallParameters -Record $config.firewallRules[0] } |
            Should-Throw -ExceptionMessage '*Multiple InterfaceType values*'
    }

    It 'validates NRPT namespaces and typed property groups' {
        $config = New-NRFixtureConfiguration
        $config.nrptRules[0].Namespace = @('')
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*non-empty Namespace*'
        $config = New-NRFixtureConfiguration
        $config.nrptRules[0].DnsSecEnable = 'true'
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*must be boolean*'
        $config = New-NRFixtureConfiguration
        $config.nrptRules[0].DisplayName = 3
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*must be string*'
    }

    It 'maps Get-NRValueFromObject enum and array values without unrolling arrays' {
        $source = [pscustomobject]@{ enumValue = [System.DayOfWeek]::Monday; values = @('a', 'b') }
        (Invoke-NRPrivateFunction -Name Get-NRValueFromObject -Parameters @{ Object = $source; Name = 'enumValue' }) | Should-Be 'Monday'
        (Invoke-NRPrivateFunction -Name Get-NRValueFromObject -Parameters @{ Object = $source; Name = 'values' }).Count | Should-Be 2
    }

    It 'rejects a bulk filter without InstanceID because it cannot be associated safely' {
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules { [pscustomobject]@{ LocalAddress = @('Any'); RemoteAddress = @('Any') } }
        { Get-NRFirewallFilterIndex } | Should-Throw -ExceptionMessage '*without InstanceID*'
    }

    It 'rejects duplicate InstanceID values in a bulk filter result' {
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules {
            @(
                [pscustomobject]@{ InstanceID = 'RuleA'; LocalAddress = @('Any'); RemoteAddress = @('Any') },
                [pscustomobject]@{ InstanceID = 'RuleA'; LocalAddress = @('Any'); RemoteAddress = @('Any') }
            )
        }
        { Get-NRFirewallFilterIndex } | Should-Throw -ExceptionMessage '*duplicate filter InstanceID*'
    }

    It 'rejects a filter index that has no filter for a Firewall rule' {
        $index = @{}
        foreach ($spec in @(Get-NRFirewallFilterSpecs)) { $index[$spec.JsonName] = @{} }
        { Get-NRFirewallFilterFromIndex -Rule ([pscustomobject]@{ Name = 'MissingRule' }) -FilterIndex $index } |
            Should-Throw -ExceptionMessage '*No address filter*'
    }

    It 'captures all Firewall rule properties' {
        $nativeRule = New-NRFixtureFirewallRuleObject -Properties ([ordered]@{
            Name = 'AllowTest'; DisplayName = 'Display'; Description = 'desc'; Group = 'group'; Enabled = 'True'
        })
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @($nativeRule) }
        $filterIndex = @{
            address = @{ AllowTest = (New-NRFixtureFirewallFilter -Type Address -Properties @{ InstanceID = 'AllowTest' }) }
            port = @{ AllowTest = (New-NRFixtureFirewallFilter -Type Port -Properties @{ InstanceID = 'AllowTest' }) }
            application = @{ AllowTest = (New-NRFixtureFirewallFilter -Type Application -Properties @{ InstanceID = 'AllowTest' }) }
            service = @{ AllowTest = (New-NRFixtureFirewallFilter -Type Service -Properties @{ InstanceID = 'AllowTest' }) }
            interface = @{ AllowTest = (New-NRFixtureFirewallFilter -Type Interface -Properties @{ InstanceID = 'AllowTest' }) }
            interfaceType = @{ AllowTest = (New-NRFixtureFirewallFilter -Type InterfaceType -Properties @{ InstanceID = 'AllowTest' }) }
            security = @{ AllowTest = (New-NRFixtureFirewallFilter -Type Security -Properties @{ InstanceID = 'AllowTest' }) }
        }
        Mock Get-NRFirewallFilterIndex -ModuleName PSNetRules { $filterIndex }
        $actual = @(Get-NRFirewallRules)
        $actual.Count | Should-Be 1
        $actual[0].name | Should-Be 'AllowTest'
        $actual[0].rule.DisplayName | Should-Be 'Display'
        $actual[0].filters.port.LocalPort | Should-BeCollection @('443')

    }

    It 'retains Native Firewall Rule and filter objects when comparison source is requested' {
        $nativeRule = New-NRFixtureFirewallRuleObject -Properties ([ordered]@{
            Name = 'Rule-A'; InstanceID = 'Rule-A'; DisplayName = 'Rule A'; Enabled = 'True'
        })
        $filters = @{}
        foreach ($type in @('Address', 'Application', 'Port', 'Service', 'Interface', 'InterfaceType', 'Security')) {
            $filters[$type] = New-NRFixtureFirewallFilter -Type $type -InstanceId 'Rule-A'
        }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @($nativeRule) }
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules { @($filters.Address) }
        Mock Get-NetFirewallApplicationFilter -ModuleName PSNetRules { @($filters.Application) }
        Mock Get-NetFirewallPortFilter -ModuleName PSNetRules { @($filters.Port) }
        Mock Get-NetFirewallServiceFilter -ModuleName PSNetRules { @($filters.Service) }
        Mock Get-NetFirewallInterfaceFilter -ModuleName PSNetRules { @($filters.Interface) }
        Mock Get-NetFirewallInterfaceTypeFilter -ModuleName PSNetRules { @($filters.InterfaceType) }
        Mock Get-NetFirewallSecurityFilter -ModuleName PSNetRules { @($filters.Security) }
        Mock Write-Progress -ModuleName PSNetRules {}

        $captured = Get-NRFirewallRules -IncludeComparisonSource
        $captured.Records.Count | Should-Be 1
        $captured.ComparisonSource.Rules.Count | Should-Be 1
        $captured.ComparisonSource.FilterIndexes.address['Rule-A'] | Should-Be $filters.Address
        $inventory = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore -CaptureSource $captured.ComparisonSource
        $inventory.Entries.Count | Should-Be 1
        $inventory.Entries[0].IsComplete | Should-Be $true
        $inventory.Entries[0].Fields['Application.Program'].Value | Should-Be 'Any'
        Should-Invoke Get-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Get-NetFirewallAddressFilter -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Get-NetFirewallApplicationFilter -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Get-NetFirewallPortFilter -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Get-NetFirewallServiceFilter -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Get-NetFirewallInterfaceFilter -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Get-NetFirewallInterfaceTypeFilter -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Get-NetFirewallSecurityFilter -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'returns an empty comparison source without querying filters when no Firewall rules exist' {
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @() }
        foreach ($commandName in @(
            'Get-NetFirewallAddressFilter', 'Get-NetFirewallApplicationFilter', 'Get-NetFirewallPortFilter',
            'Get-NetFirewallServiceFilter', 'Get-NetFirewallInterfaceFilter', 'Get-NetFirewallInterfaceTypeFilter',
            'Get-NetFirewallSecurityFilter'
        )) {
            Mock $commandName -ModuleName PSNetRules { throw 'Filter query should not run for an empty rule set.' }
        }
        Mock Write-Progress -ModuleName PSNetRules {}

        $captured = Get-NRFirewallRules -IncludeComparisonSource
        $captured.Records.Count | Should-Be 0
        $captured.ComparisonSource.Rules.Count | Should-Be 0
        $captured.ComparisonSource.FilterIndexes.Count | Should-Be 7
    }

    It 'rejects a Firewall rule with an empty name' {
        $nativeRule = [pscustomobject]@{ Name = '' }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @($nativeRule) }
        { Get-NRFirewallRules } | Should-Throw -ExceptionMessage '*empty Name*'
    }

    It 'captures NRPT rules with direct Windows-name fallback' {
        $native = [pscustomobject]@{ Name = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'; Namespace = @('.example'); NameServers = @('192.0.2.1') }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($native) }
        $actual = @(Get-NRNrptRules)
        $actual.Count | Should-Be 1
        $actual[0].id | Should-Be $native.Name
        $actual[0].Namespace[0] | Should-Be '.example'
    }

    It 'rejects an NRPT rule with an empty Windows name' {
        $native = [pscustomobject]@{ Name = '' }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($native) }
        { Get-NRNrptRules } | Should-Throw -ExceptionMessage '*empty Windows Name*'
    }

    It 'writes an empty state map and accepts a state backup without NRPT mappings' {
        $statePath = Join-Path $TestDrive 'empty-state.state.json'
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        (Read-NRStateFile $statePath).nrptRules.Count | Should-Be 0
        $backupPath = New-NRBackup -ConfigurationPath (Join-Path $TestDrive 'managed.json') `
            -CurrentState (New-NRFixtureConfiguration) -State $null
        Test-Path $backupPath | Should-Be $true
        Test-Path ($backupPath -replace '\.json$', '.state.json') | Should-Be $false
    }

    It 'removes stale Firewall entries only from the supplied current map' {
        Mock Remove-NetFirewallRule -ModuleName PSNetRules {}
        Remove-NRStaleFirewallRules -CurrentRulesByName @{ 'netrules-test' = [pscustomobject]@{} } -DesiredRules @{}
        Should-Invoke Remove-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'netrules-test' -and $PolicyStore -eq 'PersistentStore'
        }
    }

    It 'does not remove firewall entries when the desired key exists' {
        Mock Remove-NetFirewallRule -ModuleName PSNetRules {}
        Remove-NRStaleFirewallRules -CurrentRulesByName @{ keep = [pscustomobject]@{} } -DesiredRules @{ keep = [pscustomobject]@{} }
        Should-Invoke Remove-NetFirewallRule -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'removes an obsolete NRPT name that has no logical sidecar id' {
        $windowsName = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        $currentById = @{ $windowsName = [pscustomobject]@{ Name = $windowsName } }
        $nameById = @{ $windowsName = $windowsName }
        $stateMap = @{}
        Mock Remove-DnsClientNrptRule -ModuleName PSNetRules {}
        $statePath = Join-Path $TestDrive 'unmapped.state.json'
        Remove-NRStaleNrptRules -CurrentById $currentById -NameById $nameById -DesiredRules @{} -StateMap $stateMap -StatePath $statePath
        Should-Invoke Remove-DnsClientNrptRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Name -eq $windowsName -and $Force }
    }

    It 'updates only static address values and does not modify an auto-resolved keyword' {
        $id = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        Mock Update-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Mock Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Mock New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Update-NRFirewallDynamicKeyword -CurrentRecord ([pscustomobject]@{ Keyword = 'A'; AutoResolve = $false; Addresses = '10.0.0.0/8' }) `
            -DesiredRecord ([pscustomobject]@{ id = $id; Keyword = 'A'; AutoResolve = $false; Addresses = '10.1.0.0/16' }) -Id $id
        Update-NRFirewallDynamicKeyword -CurrentRecord ([pscustomobject]@{ Keyword = 'B'; AutoResolve = $true; Addresses = $null }) `
            -DesiredRecord ([pscustomobject]@{ id = $id; Keyword = 'B'; AutoResolve = $true; Addresses = $null }) -Id $id
        Should-Invoke Update-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Addresses -eq '10.1.0.0/16' -and $Append -eq $false
        }
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 0 -Exactly
        Should-Invoke New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'recreates dynamic keyword definitions when keyword attributes change' {
        $id = '{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}'
        Mock Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Mock New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Update-NRFirewallDynamicKeyword -CurrentRecord ([pscustomobject]@{ Keyword = 'Old'; AutoResolve = $false; Addresses = '10.0.0.0/8' }) `
            -DesiredRecord ([pscustomobject]@{ id = $id; Keyword = 'New'; AutoResolve = $false; Addresses = '10.1.0.0/16' }) -Id $id
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'does not remove stale dynamic keywords during the preparation phase' {
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @([pscustomobject]@{ Id = 'old'; Keyword = 'Old'; AutoResolve = $true }) }
        Mock Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Invoke-NRFirewallDynamicKeywordApply -Desired ([pscustomobject]@{ firewallDynamicKeywordAddresses = @() })
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'removes stale dynamic keywords during the final reconciliation phase' {
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @([pscustomobject]@{ Id = 'old'; Keyword = 'Old'; AutoResolve = $true }) }
        Mock Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Invoke-NRFirewallDynamicKeywordApply -Desired ([pscustomobject]@{ firewallDynamicKeywordAddresses = @() }) -RemoveStale
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Id -eq 'old' }
    }

    It 'does not remove any current Firewall rule when no dynamic keyword is recreated' {
        $current = [pscustomobject]@{ firewallDynamicKeywordAddresses = @(); firewallRules = @((New-NRFixtureFirewallRuleRecord)) }
        $desired = Copy-TestObject $current
        Mock Remove-NetFirewallRule -ModuleName PSNetRules {}
        Remove-NRRulesReferencingRecreatedDynamicKeywords -Desired $desired -Current $current
        Should-Invoke Remove-NetFirewallRule -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'converts NRPT properties for update while preserving false switch values' {
        $record = New-NRFixtureNrptRuleRecord
        $record.DAEnable = $false
        $record.DnsSecEnable = $true
        $parameters = ConvertTo-NRNrptParameters -Record $record
        $parameters.ContainsKey('DAEnable') | Should-Be $true
        $parameters.DAEnable | Should-Be $false
        $parameters.DnsSecEnable | Should-Be $true
    }

    It 'compares NRPT Windows property names with logical JSON property names' {
        $native = [pscustomobject]@{
            Namespace = @('.corp.example'); IPsecCARestriction = 'CA'; DirectAccessDnsServers = @('192.0.2.2')
            DirectAccessEnabled = $true; DirectAccessQueryIPsecEncryption = 'AES'; DirectAccessQueryIPsecRequired = $true
            DirectAccessProxyName = 'proxy'; DirectAccessProxyType = 'Manual'; NameServers = @('192.0.2.53')
            NameEncoding = 'Punycode'; DnsSecEnabled = $true; DnsSecQueryIPsecEncryption = 'AES'
            DnsSecQueryIPsecRequired = $true; DnsSecValidationRequired = $true; DisplayName = 'name'; Comment = 'comment'
        }
        $result = ConvertTo-NRNrptComparable $native
        $result.IPsecTrustAuthority | Should-Be 'CA'
        $result.DANameServers[0] | Should-Be '192.0.2.2'
        $result.DnsSecEnable | Should-Be $true
        $result.Comment | Should-Be 'comment'
    }

    It 'validates command path errors and handles no-op diff output' {
        { Read-NRConfiguration -Path (Join-Path $TestDrive 'missing.json') } | Should-Throw -ExceptionMessage '*not found*'
        $invalidPath = Join-Path $TestDrive 'invalid.json'
        Set-Content -LiteralPath $invalidPath -Value '{not-json'
        { Read-NRConfiguration -Path $invalidPath } | Should-Throw -ExceptionMessage '*Unable to parse JSON*'
        Format-NRDiff -Changes @() | Should-Be 'No changes.'
        (Get-NRStatePath -Path (Join-Path $TestDrive 'folder\rules.json')) | Should-MatchString 'rules.state.json$'
    }
}


Describe 'netrules extended branch coverage' {
    It 'handles dictionaries, custom objects, nulls and enumerable conversion branches' {
        (Get-NRProperty @{ key = $null } 'missing') | Should-Be $null
        (Get-NRPropertyNames @{ alpha = 1; beta = 2 }).Count | Should-Be 2
        (Get-NRPropertyNames ([pscustomobject]@{ alpha = 1 })).Count | Should-Be 1
        (Invoke-NRPrivateFunction -Name ConvertTo-NRJsonValue -Parameters @{ Value = [datetime]'2024-01-02T03:04:05Z' }) | Should-Be ([datetime]'2024-01-02T03:04:05Z')
        (Invoke-NRPrivateFunction -Name ConvertTo-NRJsonValue -Parameters @{ Value = [guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' }) | Should-Be ([guid]'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
        (Invoke-NRPrivateFunction -Name Get-NRCompactValue -Parameters @{ Value = $null }) | Should-Be 'null'
        (Get-NRCanonicalValue $null) | Should-Be $null
        (ConvertTo-NRCanonicalJson -InputObject ([object[]]@())) | Should-Be '[]'
    }

    It 'compares string sequences as case-sensitive multisets while retaining duplicates' {
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = @('b', 'a', 'a'); Right = @('a', 'b', 'a') }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = @('a', 'a'); Right = @('a', 'b') }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = @('a'); Right = @('A') }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = @($null, 'a'); Right = @('a', $null) }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = @(); Right = @() }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRCanonicalValuesEqual -Parameters @{ Left = @('a', [pscustomobject]@{ value = 1 }); Right = @('a', [pscustomobject]@{ value = 1 }) }) | Should-Be $true
    }

    It 'uses the PSCustomObject comparison path without changing nested diff details' {
        $before = [pscustomobject]@{
            name = 'Rule-A'
            rule = [pscustomobject]@{ Enabled = 'True'; Profile = @('Private', 'Domain'); Description = $null }
            filters = [pscustomobject]@{ port = [pscustomobject]@{ LocalPort = @('443', '8443') } }
        }
        $after = [pscustomobject]@{
            name = 'Rule-A'
            rule = [pscustomobject]@{ Enabled = 'False'; Profile = @('Domain', 'Private'); Description = $null }
            filters = [pscustomobject]@{ port = [pscustomobject]@{ LocalPort = @('443', '8443') } }
        }
        $details = @(Get-NRObjectChanges -Before $before -After $after)
        $details.Count | Should-Be 1
        $details[0] | Should-MatchString '^rule.Enabled:'
    }

    It 'compares property additions, removals, nulls and nested arrays deterministically' {
        $before = [pscustomobject]@{ retained = $null; removed = 'x'; nested = [pscustomobject]@{ values = @('b', 'a') } }
        $after = [pscustomobject]@{ retained = 'now-set'; added = 'y'; nested = [pscustomobject]@{ values = @('a', 'b') } }
        $details = @(Get-NRObjectChanges -Before $before -After $after)
        ($details -join "`n") | Should-MatchString 'added'
        ($details -join "`n") | Should-MatchString 'removed'
        ($details -join "`n") | Should-MatchString 'retained'
        ($details -join "`n") | Should-NotMatchString 'nested.values'
    }

    It 'handles null-transition checks for absent current objects and empty desired objects' {
        (Invoke-NRPrivateFunction -Name Get-NRProperty -Parameters @{ InputObject = $null; Name = 'value' }) | Should-Be $null
        (Invoke-NRPrivateFunction -Name Test-NRNullTransition -Parameters @{ Current = $null; Desired = [pscustomobject]@{ value = $null } }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRNullTransition -Parameters @{ Current = [pscustomobject]@{ value = 'present' }; Desired = [pscustomobject]@{ value = $null } }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRNullTransition -Parameters @{ Current = 'present'; Desired = 'replacement' }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRNullTransition -Parameters @{ Current = $null; Desired = @() }) | Should-Be $false
    }

    It 'reports every profile diff and no profile diff when values match' {
        $desired = New-NRFixtureConfiguration
        $current = Copy-TestObject $desired
        $current.firewallProfiles.Private.Enabled = 'False'
        $changes = @(Get-NRProfileDiff -DesiredProfiles $desired.firewallProfiles -CurrentProfiles $current.firewallProfiles)
        $changes.Count | Should-Be 1
        $changes[0].Target | Should-Be 'FirewallProfile'
        $changes[0].Key | Should-Be 'Private'
        @(Get-NRProfileDiff -DesiredProfiles $desired.firewallProfiles -CurrentProfiles $desired.firewallProfiles).Count | Should-Be 0
    }

    It 'formats all diff actions including an unknown action' {
        $text = @(Format-NRDiff -Changes @(
            (New-NRChangeRecord -Target Rule -Key add -Action Add),
            (New-NRChangeRecord -Target Rule -Key update -Action Update),
            (New-NRChangeRecord -Target Rule -Key delete -Action Delete),
            (New-NRChangeRecord -Target Rule -Key other -Action Other)
        )) -join "`n"
        $text | Should-MatchString '\+ Rule: add'
        $text | Should-MatchString '~ Rule: update'
        $text | Should-MatchString '- Rule: delete'
        $text | Should-MatchString '\? Rule: other'
    }

    It 'rejects every missing or malformed Firewall Profile shape' {
        $config = New-NRFixtureConfiguration
        $config.firewallProfiles = [pscustomobject]@{ Domain = (New-NRFixtureFirewallProfile); Private = (New-NRFixtureFirewallProfile) }
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*firewallProfiles.Public is required*'
        $config = New-NRFixtureConfiguration
        Add-Member -InputObject $config.firewallProfiles.Domain -MemberType NoteProperty -Name Unknown -Value 1
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*unsupported property*'
        $config = New-NRFixtureConfiguration
        $config.firewallProfiles.Domain.DisabledInterfaceAliases = @('Ethernet', 3)
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*DisabledInterfaceAliases must be stringArray*'
    }

    It 'validates Firewall filter collections and permits a single InterfaceType array' {
        $config = New-NRFixtureConfiguration
        $config.firewallRules[0].filters.interfaceType.InterfaceType = @('Wired')
        (Assert-NRConfiguration $config) | Should-Be $true
        (ConvertTo-NRFirewallParameters $config.firewallRules[0]).InterfaceType | Should-Be 'Wired'
        $config.firewallRules[0].filters.address.RemoteAddress = @('10.0.0.0/8', 2)
        { Assert-NRConfiguration $config } | Should-Throw -ExceptionMessage '*RemoteAddress must be stringArray*'
    }

    It 'validates required NRPT identity and duplicate IDs' {
        $ids = @{}
        $record = New-NRFixtureNrptRuleRecord
        Assert-NRNrptRule -Rule $record -Ids $ids
        { Assert-NRNrptRule -Rule $record -Ids $ids } | Should-Throw -ExceptionMessage '*Duplicate NRPT id*'
        $record = New-NRFixtureNrptRuleRecord
        $record.id = ''
        { Assert-NRNrptRule -Rule $record -Ids @{} } | Should-Throw -ExceptionMessage '*non-empty id*'
        $record = New-NRFixtureNrptRuleRecord
        $record.Namespace = @()
        { Assert-NRNrptRule -Rule $record -Ids @{} } | Should-Throw -ExceptionMessage '*at least one non-empty Namespace*'
    }

    It 'returns an empty dynamic keyword identifier set for an empty collection' {
        (Assert-NRFirewallDynamicKeywordAddresses -Addresses ([object[]]@())).Count | Should-Be 0
    }

    It 'rejects malformed optional Dynamic Keyword Address fields' {
        $base = [pscustomobject]@{ id = '{11111111-1111-1111-1111-111111111111}'; Keyword = 'KW'; Addresses = '10.0.0.0/8'; AutoResolve = $false }
        $bad = Copy-TestObject $base
        $bad.Keyword = 4
        { Assert-NRDynamicKeywordAddress -Address $bad -KnownIds @{} } | Should-Throw -ExceptionMessage '*Keyword must be string*'
        $bad = Copy-TestObject $base
        $bad.AutoResolve = $null
        { Assert-NRDynamicKeywordAddress -Address $bad -KnownIds @{} } | Should-Throw -ExceptionMessage '*must declare AutoResolve*'
    }

    It 'rejects invalid command-line configuration JSON separately from missing paths' {
        $path = Join-Path $TestDrive 'bad-configuration.json'
        Set-Content -LiteralPath $path -Value '{'
        { Invoke-NRValidate -Path $path } | Should-Throw -ExceptionMessage '*Unable to parse JSON*'
    }

    It 'fails to capture a duplicate Firewall Profile record' {
        $items = @()
        foreach ($profileName in @('Domain', 'Private', 'Public', 'Private')) {
            $item = New-NRFixtureFirewallProfile
            Add-Member -InputObject $item -MemberType NoteProperty -Name Name -Value $profileName
            $items += $item
        }
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { $items }
        { Get-NRFirewallProfiles } | Should-Throw -ExceptionMessage '*exactly one PersistentStore firewall profile*'
    }

    It 'captures the logical NRPT ID from state while retaining fallback identity for unknown rules' {
        $mapped = '{11111111-1111-1111-1111-111111111111}'
        $unmapped = '{22222222-2222-2222-2222-222222222222}'
        $records = @(
            [pscustomobject]@{ Name = $mapped; Namespace = @('.mapped'); NameServers = @('192.0.2.10') },
            [pscustomobject]@{ Name = $unmapped; Namespace = @('.unmapped'); NameServers = @('192.0.2.20') }
        )
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { $records }
        $actual = @(Get-NRNrptRules -IdByWindowsName @{ $mapped = 'logical-id' })
        $actual.Count | Should-Be 2
        @($actual.id) | Should-BeCollection -Expected @('logical-id', $unmapped)
    }

    It 'serializes the complete current snapshot with NRPT state identity' {
        $profileItems = @()
        foreach ($profileName in @('Domain', 'Private', 'Public')) {
            $item = New-NRFixtureFirewallProfile
            Add-Member -InputObject $item -MemberType NoteProperty -Name Name -Value $profileName
            $profileItems += $item
        }
        $windowsName = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        $statePath = Join-Path $TestDrive 'mapped.state.json'
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{ 'corp-dns' = $windowsName }; managedFirewallRules = @() })
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { $profileItems }
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @() }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @() }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @([pscustomobject]@{ Name = $windowsName; Namespace = @('.corp.example') }) }
        $current = Get-NRCurrentState -StatePath $statePath
        $current.nrptRules.Count | Should-Be 1
        $current.nrptRules[0].id | Should-Be 'corp-dns'
    }

    It 'converts Firewall parameters with false values and excludes null values' {
        $record = New-NRFixtureFirewallRuleRecord
        $record.rule.LooseSourceMapping = $false
        $record.rule.Owner = $null
        $record.filters.security.OverrideBlockRules = $false
        $parameters = ConvertTo-NRFirewallParameters -Record $record
        $parameters.ContainsKey('LooseSourceMapping') | Should-Be $true
        $parameters.LooseSourceMapping | Should-Be $false
        $parameters.ContainsKey('OverrideBlockRules') | Should-Be $true
        $parameters.OverrideBlockRules | Should-Be $false
        $parameters.ContainsKey('Owner') | Should-Be $false
    }

    It 'builds Firewall Profile parameters from non-null properties only' {
        $profileRecord = New-NRFixtureFirewallProfile
        $profileRecord.LogFileName = $null
        $parameters = ConvertTo-NRProfileParameters $profileRecord
        $parameters.ContainsKey('LogFileName') | Should-Be $false
        $parameters.LogMaxSizeKilobytes | Should-Be 4096
    }

    It 'distinguishes Firewall rule update from required recreation' {
        $current = New-NRFixtureFirewallRuleRecord
        $desired = Copy-TestObject $current
        (Test-NRFirewallRuleRequiresRecreation -CurrentRecord $current -DesiredRecord $desired) | Should-Be $false
        $desired.rule.Group = 'new-group'
        (Test-NRFirewallRuleRequiresRecreation -CurrentRecord $current -DesiredRecord $desired) | Should-Be $true
        $desired = Copy-TestObject $current
        $desired.rule.Description = $null
        (Test-NRFirewallRuleRequiresRecreation -CurrentRecord $current -DesiredRecord $desired) | Should-Be $true
    }

    It 'maps AutoResolve dynamic keywords without binding an Addresses parameter' {
        $parameters = New-NRDynamicKeywordParameters ([pscustomobject]@{
            id = '{11111111-1111-1111-1111-111111111111}'; Keyword = 'Dynamic'; Addresses = $null; AutoResolve = $true
        })
        $parameters.AutoResolve | Should-Be $true
        $parameters.ContainsKey('Addresses') | Should-Be $false
    }

    It 'applies existing dynamic keyword updates and skips unchanged auto-resolved addresses' {
        $id = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        $existing = [pscustomobject]@{ Id = $id; Keyword = 'KW'; AutoResolve = $false; Addresses = '10.0.0.0/8' }
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @($existing) }
        Mock Update-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Mock New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Mock Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        $desired = [pscustomobject]@{ firewallDynamicKeywordAddresses = @(
            [pscustomobject]@{ id = $id; Keyword = 'KW'; AutoResolve = $false; Addresses = '10.1.0.0/16' }
        ) }
        Invoke-NRFirewallDynamicKeywordApply -Desired $desired
        Should-Invoke Update-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 0 -Exactly
        Should-Invoke Remove-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'removes only current Firewall rules referencing a recreated dynamic keyword' {
        $id = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        $current = [pscustomobject]@{
            firewallDynamicKeywordAddresses = @([pscustomobject]@{ id = $id; Keyword = 'Old'; AutoResolve = $false; Addresses = '10.0.0.0/8' })
            firewallRules = @(
                [pscustomobject]@{ name = 'uses-keyword'; rule = [pscustomobject]@{ RemoteDynamicKeywordAddresses = @($id) } },
                [pscustomobject]@{ name = 'ordinary'; rule = [pscustomobject]@{ RemoteDynamicKeywordAddresses = @() } }
            )
        }
        $desired = [pscustomobject]@{
            firewallDynamicKeywordAddresses = @([pscustomobject]@{ id = $id; Keyword = 'New'; AutoResolve = $false; Addresses = '10.0.0.0/8' })
            firewallRules = @()
        }
        Mock Remove-NetFirewallRule -ModuleName PSNetRules {}
        Remove-NRRulesReferencingRecreatedDynamicKeywords -Desired $desired -Current $current
        Should-Invoke Remove-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Name -eq 'uses-keyword' }
    }

    It 'does not delete NRPT rules retained in the desired map' {
        $id = 'logical'
        $windowsName = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        $currentById = @{ $id = [pscustomobject]@{ Name = $windowsName } }
        $nameById = @{ $id = $windowsName }
        $stateMap = @{ $id = $windowsName }
        Mock Remove-DnsClientNrptRule -ModuleName PSNetRules {}
        Remove-NRStaleNrptRules -CurrentById $currentById -NameById $nameById -DesiredRules @{ $id = 1 } `
            -StateMap $stateMap -StatePath (Join-Path $TestDrive 'retain.state.json')
        Should-Invoke Remove-DnsClientNrptRule -ModuleName PSNetRules -Times 0 -Exactly
        $stateMap.ContainsKey($id) | Should-Be $true
    }

    It 'rejects Add-DnsClientNrptRule when it returns no generated Name' {
        $record = New-NRFixtureNrptRuleRecord
        Mock Add-DnsClientNrptRule -ModuleName PSNetRules { @() }
        { Add-NRNrptRuleAndTrack -LogicalId $record.id -Record $record -StateMap @{} -StatePath (Join-Path $TestDrive 'none.state.json') } |
            Should-Throw -ExceptionMessage '*did not return the generated Windows Name*'
    }

    It 'rejects Add-DnsClientNrptRule when it returns multiple generated Names' {
        $record = New-NRFixtureNrptRuleRecord
        Mock Add-DnsClientNrptRule -ModuleName PSNetRules { @([pscustomobject]@{ Name = 'one' }, [pscustomobject]@{ Name = 'two' }) }
        { Add-NRNrptRuleAndTrack -LogicalId $record.id -Record $record -StateMap @{} -StatePath (Join-Path $TestDrive 'many.state.json') } |
            Should-Throw -ExceptionMessage '*did not return the generated Windows Name*'
    }

    It 'preserves the existing NRPT mapping when the rule already matches' {
        $windowsName = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        $desiredRule = New-NRFixtureNrptRuleRecord
        $native = [pscustomobject]@{
            Name = $windowsName; Namespace = $desiredRule.Namespace; IPsecCARestriction = $null
            DirectAccessDnsServers = @(); DirectAccessEnabled = $false; DirectAccessQueryIPsecEncryption = $null
            DirectAccessQueryIPsecRequired = $false; DirectAccessProxyName = $null; DirectAccessProxyType = $null
            NameServers = $desiredRule.NameServers; NameEncoding = $desiredRule.NameEncoding; DnsSecEnabled = $false
            DnsSecQueryIPsecEncryption = $null; DnsSecQueryIPsecRequired = $false; DnsSecValidationRequired = $false
            DisplayName = $desiredRule.DisplayName; Comment = $desiredRule.Comment
        }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($native) }
        Mock Add-DnsClientNrptRule -ModuleName PSNetRules { throw 'Must not add' }
        Mock Remove-DnsClientNrptRule -ModuleName PSNetRules { throw 'Must not remove' }
        $stateMap = @{ $desiredRule.id = $windowsName }
        $statePath = Join-Path $TestDrive 'unchanged.state.json'
        Invoke-NRNrptApply -Desired ([pscustomobject]@{ nrptRules = @($desiredRule) }) -StateMap $stateMap -StatePath $statePath
        Should-Invoke Add-DnsClientNrptRule -ModuleName PSNetRules -Times 0 -Exactly
        Should-Invoke Remove-DnsClientNrptRule -ModuleName PSNetRules -Times 0 -Exactly
        (Read-NRStateFile $statePath).nrptRules[$desiredRule.id] | Should-Be $windowsName
    }

    It 'rejects duplicate NRPT Windows names that resolve to the same logical ID' {
        $windowsName = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        $duplicateRules = @([pscustomobject]@{ Name = $windowsName }, [pscustomobject]@{ Name = $windowsName })
        { Get-NRNrptCurrentIndex -Rules $duplicateRules -StateMap @{} } |
            Should-Throw -ExceptionMessage '*Two NRPT rules resolve to the same logical id*'
    }

    It 'fails fast on unsupported operating systems before testing elevation' {
        $originalOs = $env:OS
        try {
            $env:OS = 'NotWindows'
            { Assert-NRAdministrator } | Should-Throw -ExceptionMessage '*requires Windows*'
        }
        finally {
            $env:OS = $originalOs
        }
    }

    It 'rejects an elevated-only operation when the process is not an administrator' {
        $originalOs = $env:OS
        try {
            $env:OS = 'Windows_NT'
            Mock Test-NRIsAdministrator -ModuleName PSNetRules { return $false }

            { Assert-NRAdministrator } | Should-Throw -ExceptionMessage '*Administrator privileges are required*'
            Should-Invoke Test-NRIsAdministrator -ModuleName PSNetRules -Times 1 -Exactly
        }
        finally {
            $env:OS = $originalOs
        }
    }

    It 'allows an elevated-only operation when the process is an administrator' {
        $originalOs = $env:OS
        try {
            $env:OS = 'Windows_NT'
            Mock Test-NRIsAdministrator -ModuleName PSNetRules { return $true }

            Assert-NRAdministrator
            Should-Invoke Test-NRIsAdministrator -ModuleName PSNetRules -Times 1 -Exactly
        }
        finally {
            $env:OS = $originalOs
        }
    }

    It 'runs diff from the saved snapshot without reading the operating system' {
        $path = Join-Path $TestDrive 'diff.json'
        $configuration = New-NRFixtureConfiguration
        Write-NRJsonFile -Path $path -InputObject $configuration
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $configuration)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })

        $output = @(Invoke-NRDiff -Path $path) -join [Environment]::NewLine
        $output | Should-MatchString 'InSync'
        $output | Should-MatchString 'Other managed resources: No changes.'
    }

    It 'emits only text lines from diff and lists NewCandidate rules when the initial Desired State is empty' {
        $path = Join-Path $TestDrive 'diff-new-candidate.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        $captured = New-NRFixtureConfiguration
        Write-NRJsonFile -Path $path -InputObject $desired
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })

        $output = @(Invoke-NRDiff -Path $path)
        @($output | Where-Object { $_ -isnot [string] }).Count | Should-Be 0
        ($output -join [Environment]::NewLine) | Should-MatchString '\[NewCandidate\].*AllowHttps'
        ($output -join [Environment]::NewLine) | Should-MatchString 'Other managed resources: No changes\.'
    }

    It 're-captures into the snapshot while preserving an existing Desired State' {
        $path = Join-Path $TestDrive 'capture-refresh-existing.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $captured = New-NRFixtureConfiguration
        Mock Assert-NRAdministrator -ModuleName PSNetRules {}
        Mock New-NRCaptureSnapshot -ModuleName PSNetRules { New-NRFixtureCaptureSnapshot -Configuration $captured }
        Mock Write-Progress -ModuleName PSNetRules {}

        $captureOutput = @(Invoke-NRCapture -Path $path) -join [Environment]::NewLine
        $captureOutput | Should-MatchString 'Captured snapshot:'
        (Read-NRConfiguration -Path $path).firewallRules.Count | Should-Be 0
        (Read-NRSnapshot -Path (Get-NRSnapshotPath -Path $path)).configuration.firewallRules.Count | Should-Be 1
    }
}


Describe 'PSNetRules managed Firewall Rule workflows' {
    It 'treats DefaultExcluded as unmanaged and keeps an adopted rule managed after it matches SystemDefaults' {
        $configuration = New-NRFixtureConfiguration
        $configuration.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'DefaultRule'), (New-NRFixtureFirewallRuleRecord -Name 'ManagedRule'))
        $fields = @{ 'Rule.Enabled' = [pscustomobject]@{ Value = 'True' } }
        $persistentEntries = @(
            [pscustomobject]@{ Name = 'DefaultRule'; IsComplete = $true; Fields = $fields; MissingFilters = @(); FilterIssues = @() },
            [pscustomobject]@{ Name = 'ManagedRule'; IsComplete = $true; Fields = $fields; MissingFilters = @(); FilterIssues = @() }
        )
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $configuration
        $snapshot.comparison.persistentStore.Entries = $persistentEntries
        $snapshot.comparison.systemDefaults.Entries = @(
            [pscustomobject]@{ Name = 'DefaultRule'; IsComplete = $true; Fields = $fields; MissingFilters = @(); FilterIssues = @() },
            [pscustomobject]@{ Name = 'ManagedRule'; IsComplete = $true; Fields = $fields; MissingFilters = @(); FilterIssues = @() }
        )
        $snapshot.comparison.systemDefaults.RuleCount = 2
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'ManagedRule'))
        $state = [pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('ManagedRule') }

        $results = @(Get-NRFirewallRuleClassification -Snapshot $snapshot -Desired $desired -State $state)
        (@($results | Where-Object Name -eq 'DefaultRule')[0]).Status | Should-Be 'DefaultExcluded'
        (@($results | Where-Object Name -eq 'ManagedRule')[0]).Status | Should-Be 'InSync'
        (@($results | Where-Object Name -eq 'ManagedRule')[0]).SystemDefaults | Should-Be 'ExactMatch'
    }

    It 'shows managed rules that have become exact matches for SystemDefaults' {
        $results = @(
            [pscustomobject]@{ Name = 'ManagedDefault'; Status = 'InSync'; SystemDefaults = 'ExactMatch'; Details = @() },
            [pscustomobject]@{ Name = 'ManagedCustom'; Status = 'InSync'; SystemDefaults = 'NotFound'; Details = @() }
        )
        $output = @(Format-NRFirewallRuleClassification -Results $results) -join [Environment]::NewLine
        $output | Should-MatchString 'ManagedDefault \(SystemDefaults: ExactMatch\)'
        $output | Should-NotMatchString 'ManagedCustom'
    }

    It 'compares field dictionaries after a Snapshot JSON round-trip' {
        $fields = @{ 'Rule.Enabled' = [pscustomobject]@{ Value = 'True' } }
        $persistent = [pscustomobject]@{ Name = 'Rule-A'; IsComplete = $true; Fields = $fields }
        $defaults = [pscustomobject]@{ Name = 'Rule-A'; IsComplete = $true; Fields = $fields }
        $roundTrippedPersistent = $persistent | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $roundTrippedDefaults = $defaults | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName @{ 'Rule-A' = $roundTrippedPersistent } -SystemDefaultsByName @{ 'Rule-A' = $roundTrippedDefaults }) | Should-Be 'ExactMatch'
    }

    It 'compares string sequences as case-sensitive multisets and preserves fallback behavior' {
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('a', 'b', 'a'); Right = @('b', 'a', 'a') }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('a', 'b'); Right = @('a', 'a') }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('A'); Right = @('a') }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @($null, 'a'); Right = @('a', $null) }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('a', 1); Right = @(1, 'a', 'b') }) | Should-Be $null
    }

    It 'compares value-only comparison fields without precomputed Canonical strings' {
        $sameStringsLeft = [pscustomobject]@{ Value = @('b', 'a', 'a') }
        $sameStringsRight = [pscustomobject]@{ Value = @('a', 'b', 'a') }
        $differentDuplicates = [pscustomobject]@{ Value = @('a', 'b', 'b') }
        $differentCase = [pscustomobject]@{ Value = @('A', 'a', 'b') }
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = $sameStringsLeft; DefaultField = $sameStringsRight }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = $sameStringsLeft; DefaultField = $differentDuplicates }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = $sameStringsLeft; DefaultField = $differentCase }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = [pscustomobject]@{ Value = $true }; DefaultField = [pscustomobject]@{ Value = $true } }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = [pscustomobject]@{ Value = $true }; DefaultField = [pscustomobject]@{ Value = $false } }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = [pscustomobject]@{ Value = $null }; DefaultField = [pscustomobject]@{ Value = $null } }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = [pscustomobject]@{ Value = 'CaseSensitive' }; DefaultField = [pscustomobject]@{ Value = 'casesensitive' } }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = [pscustomobject]@{ Value = $null }; DefaultField = [pscustomobject]@{ Value = 'not-null' } }) | Should-Be $false

        $numericArrayLeft = [pscustomobject]@{ Value = [object[]]@(3, 1, 1) }
        $numericArrayRight = [pscustomobject]@{ Value = [object[]]@(1, 3, 1) }
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = $numericArrayLeft; DefaultField = $numericArrayRight }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = [pscustomobject]@{ Value = [int]1 }; DefaultField = [pscustomobject]@{ Value = [int]1 } }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = [pscustomobject]@{ Value = [object[]]@() }; DefaultField = [pscustomobject]@{ Value = [object[]]@() } }) | Should-Be $true

        $dictionaryLeft = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonPlainValue -Parameters @{ Value = [ordered]@{ z = 2; a = 1 } }
        $dictionaryRight = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonPlainValue -Parameters @{ Value = [ordered]@{ a = 1; z = 2 } }
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = [pscustomobject]@{ Value = $dictionaryLeft }; DefaultField = [pscustomobject]@{ Value = $dictionaryRight } }) | Should-Be $true

        $valueOnlyDictionaryField = @{ Value = @('b', 'a') }
        $current = [pscustomobject]@{ Value = @('a', 'b') }
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = $valueOnlyDictionaryField; DefaultField = $current }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRComparisonFieldValuesEqual -Parameters @{ PersistentField = @{ Value = @('b', 'a') }; DefaultField = @{ Value = @('a', 'b') } }) | Should-Be $true
    }

    It 'projects normalized comparison properties as Value-only fields' {
        $inputObject = [pscustomobject]@{
            Name = 'Rule-A'
            Enabled = 'True'
            RemoteAddress = @('LocalSubnet', 'Any')
            WhenCreated = [datetime]::SpecifyKind([datetime]'2026-01-02T03:04:05', [DateTimeKind]::Utc)
            Mode = [System.DayOfWeek]::Monday
            Settings = [ordered]@{ z = 2; a = 1 }
        }
        $fields = Invoke-NRPrivateFunction -Name Get-NRComparisonProperties -Parameters @{ InputObject = $inputObject; Section = 'Rule' }
        $fields.Count | Should-Be 5
        $fields['Rule.Enabled'].Value | Should-Be 'True'
        $fields['Rule.RemoteAddress'].Value | Should-BeCollection @('LocalSubnet', 'Any')
        $fields['Rule.WhenCreated'].Value | Should-Be '2026-01-02T03:04:05.0000000Z'
        $fields['Rule.Mode'].Value | Should-Be 'Monday'
        @($fields['Rule.Settings'].Value.Keys) | Should-BeCollection @('a', 'z')
        foreach ($fieldName in @('Rule.Enabled', 'Rule.RemoteAddress', 'Rule.WhenCreated', 'Rule.Mode', 'Rule.Settings')) {
            $fields[$fieldName].PSObject.Properties['Canonical'] | Should-Be $null
        }
    }

    It 'compares value-only PSCustomObject fields through the specialized comparison path' {
        $persistentFields = [pscustomobject]@{
            'Rule.Enabled' = [pscustomobject]@{ Value = $true }
            'Port.RemotePort' = [pscustomobject]@{ Value = @('443', '80') }
        }
        $defaultFields = [pscustomobject]@{
            'Port.RemotePort' = [pscustomobject]@{ Value = @('80', '443') }
            'Rule.Enabled' = [pscustomobject]@{ Value = $true }
        }
        $persistent = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $true; Fields = $persistentFields } }
        $defaults = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $true; Fields = $defaultFields } }

        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) | Should-Be 'ExactMatch'
        $defaults['Rule-A'].Fields.'Rule.Enabled' = [pscustomobject]@{ Value = $false }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) | Should-Be 'Mismatch'
    }

    It 'compares PSCustomObject comparison fields by name and Value' {
        $persistentFields = [pscustomobject]@{
            'Rule.Enabled' = [pscustomobject]@{ Value = 'True' }
            'Port.RemotePort' = [pscustomobject]@{ Value = @('443') }
        }
        $defaultFields = [pscustomobject]@{
            'Rule.Enabled' = [pscustomobject]@{ Value = 'True' }
            'Port.RemotePort' = [pscustomobject]@{ Value = @('443') }
        }
        $persistent = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $true; Fields = $persistentFields } }
        $defaults = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $true; Fields = $defaultFields } }

        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) | Should-Be 'ExactMatch'

        $defaults['Rule-A'].Fields = [pscustomobject]@{
            'Rule.Enabled' = [pscustomobject]@{ Value = 'True' }
        }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) | Should-Be 'Mismatch'

        $defaults['Rule-A'].Fields = [pscustomobject]@{
            'Rule.Enabled' = [pscustomobject]@{ Value = 'True' }
            'Port.LocalPort' = [pscustomobject]@{ Value = @('443') }
        }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) | Should-Be 'Mismatch'

        $defaults['Rule-A'].Fields = [pscustomobject]@{
            'Rule.Enabled' = [pscustomobject]@{ Value = 'False' }
            'Port.RemotePort' = [pscustomobject]@{ Value = @('443') }
        }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) | Should-Be 'Mismatch'
    }

    It 'updates the existing desired record when adopting with Update' {
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A' -LocalPort '443'))
        $captured = New-NRFixtureFirewallRuleRecord -Name 'Rule-A' -LocalPort '8443'
        $state = [pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A') }

        $updated = Invoke-NRPrivateFunction -Name Set-NRAdoptedConfiguration -Parameters @{
            Desired = $desired
            State = $state
            Names = @('Rule-A')
            CurrentByName = @{ 'Rule-A' = $captured }
            Update = $true
        }

        $updated.Desired.firewallRules.Count | Should-Be 1
        $updated.Desired.firewallRules[0].filters.port.LocalPort | Should-BeCollection @('8443')
        $updated.State.managedFirewallRules | Should-BeCollection @('Rule-A')
    }

    It 'adopts exactly the NewCandidate rules into desired JSON and managed state' {
        $path = Join-Path $TestDrive 'adopt.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration)
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $snapshot
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        Mock New-NRFileBackup -ModuleName PSNetRules { @() }

        $result = @(Invoke-NRAdopt -Path $path -New -Confirm:$false) -join [Environment]::NewLine
        $result | Should-MatchString 'Adopted 1 Firewall rules.'
        (Read-NRConfiguration -Path $path).firewallRules.Count | Should-Be 1
        ((Read-NRStateFile -Path (Get-NRStatePath -Path $path)).managedFirewallRules -contains 'AllowHttps') | Should-Be $true
    }

    It 'restores a DeletePending rule to Desired State when explicitly adopted with Update' {
        $path = Join-Path $TestDrive 'adopt-update-tombstone.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration)
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $snapshot
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('AllowHttps') })
        Mock New-NRFileBackup -ModuleName PSNetRules { @() }

        $result = @(Invoke-NRAdopt -Path $path -Update -Name 'AllowHttps' -Confirm:$false) -join [Environment]::NewLine
        $result | Should-MatchString 'Updated 1 Firewall rules.'
        (Read-NRConfiguration -Path $path).firewallRules.Count | Should-Be 1
        ((Read-NRStateFile -Path (Get-NRStatePath -Path $path)).managedFirewallRules -contains 'AllowHttps') | Should-Be $true
    }

    It 'generates a reviewable script without changing the Firewall or the management files' {
        $path = Join-Path $TestDrive 'generate.json'
        $configuration = New-NRFixtureConfiguration
        Write-NRJsonFile -Path $path -InputObject $configuration
        $capturedConfiguration = New-NRFixtureConfiguration
        $capturedConfiguration.firewallRules = @()
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $capturedConfiguration)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('AllowHttps') })
        $outputPath = Join-Path $TestDrive 'generated.ps1'

        $result = @(Invoke-NRGenerate -Path $path -OutputPath $outputPath) -join [Environment]::NewLine
        $result | Should-MatchString 'Generated:'
        $generated = Get-Content -LiteralPath $outputPath -Raw
        $generated | Should-MatchString '#requires -RunAsAdministrator'
        $generated | Should-MatchString 'Generated by PSNetRules generate'
        $generated | Should-NotMatchString 'EXECUTE GENERATED PLAN'
        $generated | Should-NotMatchString 'Import-Module'
        $generated | Should-NotMatchString 'Get-NRFirewallRuleComparisonInventory'
        $generated | Should-NotMatchString 'Save-NRGeneratedNrptState'
        $generated | Should-MatchString 'New-NetFirewallRule'
        $generated | Should-MatchString 'Run capture, then diff'
        (Read-NRConfiguration -Path $path).firewallRules.Count | Should-Be 1
    }
    It 'previews dynamic keyword address updates without passing unsupported WhatIf parameters' {
        $path = Join-Path $TestDrive 'generate-dynamic-update.json'
        $id = '{eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee}'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        $desired.firewallDynamicKeywordAddresses = @([pscustomobject]@{
            id = $id; Keyword = 'TestKeyword'; Addresses = '192.0.2.20'; AutoResolve = $false
        })
        Write-NRJsonFile -Path $path -InputObject $desired

        $captured = New-NRFixtureConfiguration
        $captured.firewallRules = @()
        $captured.firewallDynamicKeywordAddresses = @([pscustomobject]@{
            id = $id; Keyword = 'TestKeyword'; Addresses = '192.0.2.10'; AutoResolve = $false
        })
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        $outputPath = Join-Path $TestDrive 'generated-dynamic-update.ps1'

        $result = @(Invoke-NRGenerate -Path $path -OutputPath $outputPath) -join [Environment]::NewLine
        $result | Should-MatchString 'Generated:'
        $generated = Get-Content -LiteralPath $outputPath -Raw
        $generated | Should-MatchString 'if \(\$WhatIfPreference\) \{ Write-Output .*WHATIF: Update-NetFirewallDynamicKeywordAddress'
        $generated | Should-MatchString 'else \{ Update-NetFirewallDynamicKeywordAddress'
        $generated | Should-NotMatchString 'Update-NetFirewallDynamicKeywordAddress.*-WhatIf'
        $generated | Should-MatchString 'WhatIf preview completed; no changes were applied.'
    }

}

Describe 'netrules additional coverage and boundary failure paths' {
    It 'creates canonical JSON from normalized comparison values' {
        $cases = New-Object 'System.Collections.Generic.List[object]'
        $cases.Add([pscustomobject]@{ Value = $null; Expected = 'null' })
        $cases.Add([pscustomobject]@{ Value = 'CaseSensitive'; Expected = '"CaseSensitive"' })
        $cases.Add([pscustomobject]@{ Value = [ordered]@{ z = 2; a = 1 }; Expected = '{"a":1,"z":2}' })
        $cases.Add([pscustomobject]@{ Value = [object[]]@('b', 'a', 'b'); Expected = '["a","b","b"]' })
        $cases.Add([pscustomobject]@{
            Value = [object[]]@([object[]]@('z', 'a'), [object[]]@('d', 'c'))
            Expected = '[["a","z"],["c","d"]]'
        })
        $cases.Add([pscustomobject]@{
            Value = [object[]]@([ordered]@{ z = @(2, 1); a = 'x' }, [ordered]@{ b = $true })
            Expected = '[{"a":"x","z":[2,1]},{"b":true}]'
        })

        foreach ($case in $cases) {
            $plain = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonPlainValue -Parameters @{ Value = $case.Value }
            $actual = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonCanonicalPlainValue -Parameters @{ Value = $plain }
            $actual | Should-Be $case.Expected
        }

        $emptyArray = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonCanonicalPlainValue -Parameters @{ Value = ([object[]]@()) }
        $emptyArray | Should-Be '[]'
    }

    It 'canonicalizes empty arrays and dictionaries without losing their JSON shape' {
        (ConvertTo-NRCanonicalJson -InputObject ([object[]]@())) | Should-Be '[]'
        (ConvertTo-NRCanonicalJson -InputObject @{}) | Should-Be '{}'
        (ConvertTo-NRCanonicalJson -InputObject ([pscustomobject]@{ b = 2; a = 1 })) | Should-Be '{"a":1,"b":2}'
    }

    It 'converts unsupported reference objects to stable strings' {
        $value = [pscustomobject]@{ Name = 'ReferenceObject' }
        (Invoke-NRPrivateFunction -Name ConvertTo-NRJsonValue -Parameters @{ Value = $value }) | Should-Be '@{Name=ReferenceObject}'
    }

    It 'validates array fields for null, scalar, and enumerable values' {
        { Assert-NRArrayField -Object ([pscustomobject]@{ items = $null }) -Field items } | Should-Throw -ExceptionMessage '*must be an array*'
        { Assert-NRArrayField -Object ([pscustomobject]@{ items = 'one' }) -Field items } | Should-Throw -ExceptionMessage '*must be an array*'
        { Assert-NRArrayField -Object ([pscustomobject]@{ items = [pscustomobject]@{ value = 1 } }) -Field items } | Should-Throw -ExceptionMessage '*must be an array*'
        Assert-NRArrayField -Object ([pscustomobject]@{ items = @() }) -Field items
    }

    It 'handles every field kind and rejects unknown kinds' {
        (Test-NRFieldValue -Value 'text' -Kind string) | Should-Be $true
        (Test-NRFieldValue -Value $true -Kind boolean) | Should-Be $true
        (Test-NRFieldValue -Value 1 -Kind number) | Should-Be $true
        (Test-NRFieldValue -Value 'text' -Kind scalar) | Should-Be $true
        (Test-NRFieldValue -Value @('a') -Kind stringArray) | Should-Be $true
        (Test-NRFieldValue -Value @('a') -Kind stringOrArray) | Should-Be $true
        (Test-NRFieldValue -Value 'text' -Kind unknown) | Should-Be $false
        Assert-NRFieldType -Object ([pscustomobject]@{ enabled = $null }) -Field enabled -Kind boolean -Context test
    }

    It 'calculates keyed collection changes independently from full configuration diff' {
        $desired = @([pscustomobject]@{ id = 'new'; value = 1 }, [pscustomobject]@{ id = 'change'; value = 2 })
        $current = @([pscustomobject]@{ id = 'change'; value = 1 }, [pscustomobject]@{ id = 'remove'; value = 3 })
        $changes = @(Get-NRKeyedCollectionDiff -DesiredItems $desired -CurrentItems $current -KeyProperty id -Target Example)
        $changes.Count | Should-Be 3
        @($changes | Where-Object Action -eq Add).Count | Should-Be 1
        @($changes | Where-Object Action -eq Update).Count | Should-Be 1
        @($changes | Where-Object Action -eq Delete).Count | Should-Be 1
        @(Get-NRKeyedCollectionDiff -DesiredItems @() -CurrentItems @() -KeyProperty id -Target Example).Count | Should-Be 0
    }

    It 'includes detailed changes when formatting an update' {
        $change = New-NRChangeRecord -Target FirewallRule -Key RuleA -Action Update -Details @('rule.Enabled: true -> false')
        (@(Format-NRDiff -Changes @($change)) -join "`n") | Should-MatchString 'rule.Enabled: true -> false'
    }

    It 'writes a sorted empty and populated state map' {
        $path = Join-Path $TestDrive 'ordered.state.json'
        Write-NRStateFile -Path $path -State ([pscustomobject]@{ nrptRules = @{ z = 'Z'; a = 'A' }; managedFirewallRules = @() })
        $json = Get-Content -LiteralPath $path -Raw
        ($json.IndexOf('"a"') -lt $json.IndexOf('"z"')) | Should-Be $true
        (Read-NRStateFile -Path $path).nrptRules['a'] | Should-Be 'A'
    }

    It 'queries each filter collection once for one hundred Firewall rules and reports mapping progress' {
        $ruleCount = 100
        $testRules = New-Object 'System.Collections.Generic.List[object]'
        $addressFilters = New-Object 'System.Collections.Generic.List[object]'
        $portFilters = New-Object 'System.Collections.Generic.List[object]'
        $applicationFilters = New-Object 'System.Collections.Generic.List[object]'
        $serviceFilters = New-Object 'System.Collections.Generic.List[object]'
        $interfaceFilters = New-Object 'System.Collections.Generic.List[object]'
        $interfaceTypeFilters = New-Object 'System.Collections.Generic.List[object]'
        $securityFilters = New-Object 'System.Collections.Generic.List[object]'

        for ($index = 1; $index -le $ruleCount; $index++) {
            $name = 'Rule{0:D3}' -f $index
            $testRules.Add([pscustomobject]@{
                Name = $name; DisplayName = $name; Description = ''; Group = ''; Enabled = 'True'
                Profile = @('Private'); Platform = @(); Direction = 'Inbound'; Action = 'Allow'
                EdgeTraversalPolicy = 'Block'; LooseSourceMapping = $false; LocalOnlyMapping = $false
                Owner = $null; RemoteDynamicKeywordAddresses = @()
            })
            $addressFilters.Add([pscustomobject]@{ InstanceID = $name; LocalAddress = 'Any'; RemoteAddress = @('Any') })
            $portFilters.Add([pscustomobject]@{ InstanceID = $name; Protocol = 'TCP'; LocalPort = [string]$index; RemotePort = 'Any'; IcmpType = $null; DynamicTarget = 'Any' })
            $applicationFilters.Add([pscustomobject]@{ InstanceID = $name; Program = 'Any'; Package = 'Any' })
            $serviceFilters.Add([pscustomobject]@{ InstanceID = $name; Service = 'Any' })
            $interfaceFilters.Add([pscustomobject]@{ InstanceID = $name; InterfaceAlias = 'Any' })
            $interfaceTypeFilters.Add([pscustomobject]@{ InstanceID = $name; InterfaceType = 'Any' })
            $securityFilters.Add([pscustomobject]@{
                InstanceID = $name; LocalUser = 'Any'; RemoteUser = 'Any'; RemoteMachine = 'Any'
                Authentication = 'NotRequired'; Encryption = 'NotRequired'; OverrideBlockRules = $false
            })
        }

        Mock Get-NetFirewallRule -ModuleName PSNetRules { $testRules.ToArray() }
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules { $addressFilters.ToArray() }
        Mock Get-NetFirewallPortFilter -ModuleName PSNetRules { $portFilters.ToArray() }
        Mock Get-NetFirewallApplicationFilter -ModuleName PSNetRules { $applicationFilters.ToArray() }
        Mock Get-NetFirewallServiceFilter -ModuleName PSNetRules { $serviceFilters.ToArray() }
        Mock Get-NetFirewallInterfaceFilter -ModuleName PSNetRules { $interfaceFilters.ToArray() }
        Mock Get-NetFirewallInterfaceTypeFilter -ModuleName PSNetRules { $interfaceTypeFilters.ToArray() }
        Mock Get-NetFirewallSecurityFilter -ModuleName PSNetRules { $securityFilters.ToArray() }
        Mock Write-Progress -ModuleName PSNetRules {}

        $captured = @(Get-NRFirewallRules)
        $captured.Count | Should-Be $ruleCount
        $captured[0].filters.port.LocalPort | Should-BeCollection @('1')
        $captured[99].filters.port.LocalPort | Should-BeCollection @('100')
        foreach ($cmdlet in @(
            'Get-NetFirewallAddressFilter', 'Get-NetFirewallPortFilter', 'Get-NetFirewallApplicationFilter',
            'Get-NetFirewallServiceFilter', 'Get-NetFirewallInterfaceFilter',
            'Get-NetFirewallInterfaceTypeFilter', 'Get-NetFirewallSecurityFilter'
        )) {
            Should-Invoke $cmdlet -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
                $All -and $PolicyStore -eq 'PersistentStore'
            }
        }
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times $ruleCount -Exactly -ParameterFilter {
            $Status -like 'Mapping Firewall rule filters:*'
        }
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 7 -Exactly -ParameterFilter {
            $Id -eq 2 -and $Status -like 'Reading *'
        }
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 7 -Exactly -ParameterFilter {
            $Id -eq 2 -and $Status -like 'Loaded *'
        }
    }

    It 'passes PersistentStore to Firewall rule enumeration' {
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @() }
        @(Get-NRFirewallRules).Count | Should-Be 0
        Should-Invoke Get-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $PolicyStore -eq 'PersistentStore'
        }
    }

    It 'stops capture when a required Firewall profile read fails' {
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { throw 'profile provider failed' }
        { Get-NRFirewallProfiles } | Should-Throw -ExceptionMessage '*profile provider failed*'
    }

    It 'stops capture when NRPT enumeration fails' {
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { throw 'NRPT provider failed' }
        { Get-NRNrptRules } | Should-Throw -ExceptionMessage '*NRPT provider failed*'
    }

    It 'maps state sidecar identifiers while capturing all current state collections' {
        $logicalId = 'corp-dns'
        $windowsName = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'
        $path = Join-Path $TestDrive 'capture-map.state.json'
        Write-NRStateFile -Path $path -State ([pscustomobject]@{ nrptRules = @{ $logicalId = $windowsName }; managedFirewallRules = @() })
        $profileRecords = @()
        foreach ($profileName in @('Domain', 'Private', 'Public')) {
            $profileRecord = New-NRFixtureFirewallProfile
            Add-Member -InputObject $profileRecord -MemberType NoteProperty -Name Name -Value $profileName
            $profileRecords += $profileRecord
        }
        $nativeNrpt = [pscustomobject]@{ Name = $windowsName; Namespace = @('.corp.example') }
        Mock Get-NetFirewallProfile -ModuleName PSNetRules { $profileRecords }
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @() }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @() }
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($nativeNrpt) }
        $state = Get-NRCurrentState -StatePath $path
        $state.nrptRules[0].id | Should-Be $logicalId
    }

    It 'creates a missing Dynamic Keyword Address during desired-state reconciliation' {
        $id = '{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}'
        $record = [pscustomobject]@{ id = $id; Keyword = 'Static'; Addresses = '192.0.2.20'; AutoResolve = $false }
        Mock Get-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules { @() }
        Mock New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules {}
        Invoke-NRFirewallDynamicKeywordApply -Desired ([pscustomobject]@{ firewallDynamicKeywordAddresses = @($record) })
        Should-Invoke New-NetFirewallDynamicKeywordAddress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Id -eq $id -and $Addresses -eq '192.0.2.20'
        }
    }

    It 'clears optional NRPT fields by removing and recreating the existing rule' {
        $record = New-NRFixtureNrptRuleRecord
        $windowsName = '{cccccccc-cccc-cccc-cccc-cccccccccccc}'
        $native = [pscustomobject]@{
            Name = $windowsName; Namespace = $record.Namespace; IPsecCARestriction = 'CA'
            DirectAccessDnsServers = @(); DirectAccessEnabled = $false; DirectAccessQueryIPsecEncryption = $null
            DirectAccessQueryIPsecRequired = $false; DirectAccessProxyName = $null; DirectAccessProxyType = $null
            NameServers = $record.NameServers; NameEncoding = $record.NameEncoding; DnsSecEnabled = $false
            DnsSecQueryIPsecEncryption = $null; DnsSecQueryIPsecRequired = $false; DnsSecValidationRequired = $false
            DisplayName = $record.DisplayName; Comment = $record.Comment
        }
        $newWindowsName = '{dddddddd-dddd-dddd-dddd-dddddddddddd}'
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @($native) }
        Mock Remove-DnsClientNrptRule -ModuleName PSNetRules {}
        Mock Add-DnsClientNrptRule -ModuleName PSNetRules { [pscustomobject]@{ Name = $newWindowsName } }
        $stateMap = @{ $record.id = $windowsName }
        $statePath = Join-Path $TestDrive 'nrpt-recreate.state.json'
        Invoke-NRNrptApply -Desired ([pscustomobject]@{ nrptRules = @($record) }) -StateMap $stateMap -StatePath $statePath
        Should-Invoke Remove-DnsClientNrptRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Name -eq $windowsName -and $Force }
        Should-Invoke Add-DnsClientNrptRule -ModuleName PSNetRules -Times 1 -Exactly
        (Read-NRStateFile -Path $statePath).nrptRules[$record.id] | Should-Be $newWindowsName
    }

}

Describe 'PSNetRules classification formatter helpers' {
    It 'rejects a non-string summary renderer result instead of leaking it to the output stream' {
        Mock Format-NRFirewallClassificationSummary -ModuleName PSNetRules { 42 }
        { Format-NRFirewallRuleClassification -Results @() } | Should-Throw -ExceptionMessage '*summary renderer produced a non-string*'
    }

    It 'rejects a non-string classification detail instead of leaking it to the output stream' {
        Mock Format-NRFirewallClassificationItem -ModuleName PSNetRules { 42 }
        $result = [pscustomobject]@{
            Name = 'Rule-A'
            Status = 'NewCandidate'
            SystemDefaults = 'Mismatch'
        }
        { Format-NRFirewallRuleClassification -Results @($result) } | Should-Throw -ExceptionMessage '*item renderer produced a non-string*'
    }

    It 'renders present and missing exclusions when their statuses are selected' {
        $results = @(
            [pscustomobject]@{ Name = 'Excluded-Rule'; DisplayName = 'Excluded Rule'; Status = 'Excluded'; SystemDefaults = 'NotEvaluated'; Details = @() },
            [pscustomobject]@{ Name = 'Gone-Excluded-Rule'; DisplayName = 'Gone Excluded Rule'; Status = 'ExcludedMissing'; SystemDefaults = 'NotEvaluated'; Details = @() }
        )
        $presentOutput = @(Format-NRFirewallRuleClassification -Results $results -Status Excluded) -join [Environment]::NewLine
        $missingOutput = @(Format-NRFirewallRuleClassification -Results $results -Status ExcludedMissing) -join [Environment]::NewLine
        $presentOutput | Should-MatchString '\[Excluded\].*Excluded-Rule'
        $missingOutput | Should-MatchString '\[ExcludedMissing\].*Gone-Excluded-Rule'
        $presentOutput | Should-NotMatchString 'Gone-Excluded-Rule'
        $missingOutput | Should-NotMatchString '(?m)^\s*\[ExcludedMissing\]\s+Excluded-Rule(?:\s|$)'
    }

    It 'includes exact InSync details in the default output and respects a different status filter' {
        $result = [pscustomobject]@{
            Name = 'Rule-A'
            DisplayName = 'Rule A'
            Status = 'InSync'
            SystemDefaults = 'ExactMatch'
            Details = @('same as default')
        }
        $allOutput = @(Format-NRFirewallRuleClassification -Results @($result)) -join [Environment]::NewLine
        $filteredOutput = @(Format-NRFirewallRuleClassification -Results @($result) -Status NewCandidate) -join [Environment]::NewLine
        $allOutput | Should-MatchString 'same as default'
        $filteredOutput | Should-NotMatchString 'same as default'
    }
}

Describe 'PSNetRules classification helper behavior' {
    It 'returns the configured detail status or the complete default detail status set' {
        $defaultStatuses = @(Invoke-NRPrivateFunction -Name Get-NRFirewallClassificationDetailStatuses -Parameters @{ Status = '' })
        $defaultStatuses.Count | Should-Be 7
        ($defaultStatuses -contains 'NewCandidate') | Should-Be $true
        ($defaultStatuses -contains 'Rename') | Should-Be $true
        ($defaultStatuses -contains 'DeleteComplete') | Should-Be $true

        $filteredStatuses = @(Invoke-NRPrivateFunction -Name Get-NRFirewallClassificationDetailStatuses -Parameters @{ Status = 'InSync' })
        $filteredStatuses.Count | Should-Be 1
        $filteredStatuses[0] | Should-Be 'InSync'
    }

    It 'includes details for configured statuses and exact InSync only when requested' {
        $candidate = [pscustomobject]@{ Status = 'NewCandidate'; SystemDefaults = 'Mismatch' }
        $inSync = [pscustomobject]@{ Status = 'InSync'; SystemDefaults = 'ExactMatch' }
        $otherInSync = [pscustomobject]@{ Status = 'InSync'; SystemDefaults = 'Mismatch' }
        (Invoke-NRPrivateFunction -Name Test-NRFirewallClassificationItemHasDetails -Parameters @{ Item = $candidate; DetailStatuses = @('NewCandidate'); IncludeExactInSync = $false }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRFirewallClassificationItemHasDetails -Parameters @{ Item = $inSync; DetailStatuses = @('NewCandidate'); IncludeExactInSync = $true }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRFirewallClassificationItemHasDetails -Parameters @{ Item = $inSync; DetailStatuses = @('NewCandidate'); IncludeExactInSync = $false }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRFirewallClassificationItemHasDetails -Parameters @{ Item = $otherInSync; DetailStatuses = @('NewCandidate'); IncludeExactInSync = $true }) | Should-Be $false
    }
}

Describe 'PSNetRules extracted reconciliation helpers' {
    It 'requires a managed Firewall name array and removes duplicate names when writing' {
        { Invoke-NRPrivateFunction -Name Get-NRManagedFirewallRuleNames -Parameters @{ Value = $null } } |
            Should-Throw -ExceptionMessage '*must be an array of strings*'
        { Invoke-NRPrivateFunction -Name Get-NRManagedFirewallRuleNames -Parameters @{ Value = 'Rule-A' } } |
            Should-Throw -ExceptionMessage '*must be an array of strings*'
        @(Invoke-NRPrivateFunction -Name Get-NRManagedFirewallRuleNames -Parameters @{ Value = @('Rule-A', 'Rule-A') }).Count | Should-Be 1
    }

    It 'rejects nested array entries and duplicate names when strict validation is requested' {
        $nestedEntry = New-Object 'System.Object[]' 2
        $nestedEntry[0] = [object[]]@('Rule-A', 'Rule-B')
        $nestedEntry[1] = 'Rule-C'
        { Invoke-NRPrivateFunction -Name Get-NRManagedFirewallRuleNames -Parameters @{ Value = $nestedEntry } } |
            Should-Throw -ExceptionMessage '*entries must be scalar strings*'
        { Invoke-NRPrivateFunction -Name Get-NRManagedFirewallRuleNames -Parameters @{ Value = @('') } } |
            Should-Throw -ExceptionMessage '*Name cannot be empty*'
        { Invoke-NRPrivateFunction -Name Get-NRManagedFirewallRuleNames -Parameters @{ Value = @('Rule-A', 'Rule-A'); RejectDuplicates = $true } } |
            Should-Throw -ExceptionMessage '*Duplicate managed Firewall rule Name*'
    }

    It 'selects only existing dynamic keyword definitions whose recreation attributes changed' {
        $current = @{
            keywordChanged = [pscustomobject]@{ Keyword = 'old'; AutoResolve = $false }
            resolveChanged = [pscustomobject]@{ Keyword = 'same'; AutoResolve = $false }
            unchanged = [pscustomobject]@{ Keyword = 'same'; AutoResolve = $true }
        }
        $desired = @{
            keywordChanged = [pscustomobject]@{ Keyword = 'new'; AutoResolve = $false }
            resolveChanged = [pscustomobject]@{ Keyword = 'same'; AutoResolve = $true }
            unchanged = [pscustomobject]@{ Keyword = 'same'; AutoResolve = $true }
            added = [pscustomobject]@{ Keyword = 'added'; AutoResolve = $true }
        }
        $ids = @(Invoke-NRPrivateFunction -Name Get-NRDynamicKeywordRecreationIds -Parameters @{ CurrentById = $current; DesiredById = $desired })
        $ids.Count | Should-Be 2
        ($ids -contains 'keywordChanged') | Should-Be $true
        ($ids -contains 'resolveChanged') | Should-Be $true
    }

    It 'tests Firewall rule references against the recreation set' {
        $record = [pscustomobject]@{
            rule = [pscustomobject]@{ RemoteDynamicKeywordAddresses = @('id-a', 'id-b') }
        }
        (Invoke-NRPrivateFunction -Name Test-NRFirewallRuleReferencesDynamicKeyword -Parameters @{ Record = $record; DynamicKeywordIds = @('id-b') }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRFirewallRuleReferencesDynamicKeyword -Parameters @{ Record = $record; DynamicKeywordIds = @('id-c') }) | Should-Be $false
    }

    It 'retains managed Firewall names that still exist or remain desired and retires absent tombstones' {
        $names = @(Invoke-NRPrivateFunction -Name Get-NRCaptureManagedFirewallRuleNames -Parameters @{
            CurrentFirewallRules = @([pscustomobject]@{ name = 'current-rule' })
            DesiredFirewallRules = @([pscustomobject]@{ name = 'desired-rule' })
            PreviouslyManagedNames = @('current-rule', 'desired-rule', 'deleted-rule')
        })
        $names.Count | Should-Be 2
        ($names -contains 'current-rule') | Should-Be $true
        ($names -contains 'desired-rule') | Should-Be $true
        ($names -contains 'deleted-rule') | Should-Be $false
    }
}

Describe 'PSNetRules capture preparation helpers' {
    It 'builds an initial Desired State with no managed Firewall Rules and preserves other captured resources' {
        $profiles = @([pscustomobject]@{ Name = 'Domain' })
        $keywords = @([pscustomobject]@{ id = 'keyword-a' })
        $nrpt = @([pscustomobject]@{ id = 'nrpt-a' })
        $snapshot = [pscustomobject]@{
            configuration = [pscustomobject]@{
                schemaVersion = 1
                firewallProfiles = $profiles
                firewallDynamicKeywordAddresses = $keywords
                nrptRules = $nrpt
                firewallRules = @([pscustomobject]@{ name = 'captured-rule' })
            }
        }
        $desired = Invoke-NRPrivateFunction -Name New-NRInitialDesiredConfiguration -Parameters @{ Snapshot = $snapshot }
        $desired.schemaVersion | Should-Be 1
        @($desired.firewallRules).Count | Should-Be 0
        @($desired.excludedFirewallRules).Count | Should-Be 0
        $desired.firewallProfiles[0].Name | Should-Be 'Domain'
        $desired.firewallDynamicKeywordAddresses[0].id | Should-Be 'keyword-a'
        $desired.nrptRules[0].id | Should-Be 'nrpt-a'
    }

    It 'keeps excluded names out of the managed inventory during capture' {
        $statePath = Join-Path $TestDrive 'capture-excluded-managed-state.json'
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{
            nrptRules = @{}
            managedFirewallRules = @('Excluded-Rule', 'Managed-Rule')
        })
        $snapshot = [pscustomobject]@{
            configuration = [pscustomobject]@{
                firewallRules = @([pscustomobject]@{ name = 'Excluded-Rule' }, [pscustomobject]@{ name = 'Managed-Rule' })
            }
        }
        $desired = [pscustomobject]@{
            firewallRules = @()
            excludedFirewallRules = @('Excluded-Rule')
        }

        Invoke-NRPrivateFunction -Name Update-NRCaptureManagedFirewallState -Parameters @{
            StatePath = $statePath; Snapshot = $snapshot; Desired = $desired
        }

        @((Read-NRStateFile -Path $statePath).managedFirewallRules) | Should-BeCollection @('Managed-Rule')
    }

    It 'updates the state sidecar with currently present or desired managed rule names' {
        $statePath = Join-Path $TestDrive 'capture-managed-state.json'
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{
            nrptRules = @{ logical = 'windows-name' }
            managedFirewallRules = @('retained', 'removed')
        })
        $snapshot = [pscustomobject]@{
            configuration = [pscustomobject]@{
                firewallRules = @([pscustomobject]@{ name = 'current' }, [pscustomobject]@{ name = 'retained' })
            }
        }
        $desired = [pscustomobject]@{
            firewallRules = @([pscustomobject]@{ name = 'desired' })
        }
        Invoke-NRPrivateFunction -Name Update-NRCaptureManagedFirewallState -Parameters @{
            StatePath = $statePath
            Snapshot = $snapshot
            Desired = $desired
        }
        $state = Read-NRStateFile -Path $statePath
        $state.managedFirewallRules.Count | Should-Be 2
        ($state.managedFirewallRules -contains 'retained') | Should-Be $true
        ($state.managedFirewallRules -contains 'desired') | Should-Be $true
        ($state.managedFirewallRules -contains 'current') | Should-Be $false
        ($state.managedFirewallRules -contains 'removed') | Should-Be $false
        $state.nrptRules.logical | Should-Be 'windows-name'
    }
}

Describe 'PSNetRules comparison inventory and state normalization' {
    It 'round-trips an explicitly empty managed Firewall rule inventory' {
        $path = Join-Path $TestDrive 'empty-managed-rules.state.json'
        Write-NRStateFile -Path $path -State ([pscustomobject]@{
            nrptRules = @{}
            managedFirewallRules = @()
        })

        $json = Get-Content -LiteralPath $path -Raw
        $json | Should-MatchString '"managedFirewallRules"\s*:\s*\[\s*\]'
        (Read-NRStateFile -Path $path).managedFirewallRules.Count | Should-Be 0
    }

    It 'rejects duplicate managed Firewall names in a state file' {
        $path = Join-Path $TestDrive 'duplicate-managed-rules.state.json'
        [System.IO.File]::WriteAllText($path, '{"schemaVersion":1,"nrptRules":{},"managedFirewallRules":["Rule-A","Rule-A"]}')
        { Read-NRStateFile -Path $path } | Should-Throw -ExceptionMessage '*Duplicate managed Firewall rule Name*'
    }

    It 'normalizes a nested single-array wrapper without treating it as a rule record' {
        $records = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'), (New-NRFixtureFirewallRuleRecord -Name 'Rule-B'))
        $nested = ,$records
        $normalized = Invoke-NRPrivateFunction -Name ConvertTo-NRObjectArray -Parameters @{ Value = $nested }
        $normalized.Count | Should-Be 2
        @($normalized | ForEach-Object name) | Should-BeCollection @('Rule-A', 'Rule-B')
    }

    It 'builds PersistentStore comparison inventory from captured Native objects without re-querying cmdlets' {
        $rule = New-NRFixtureFirewallRuleObject -Properties ([ordered]@{
            Name = 'Rule-A'; InstanceID = 'Rule-A'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'
        })
        $nativeIndexes = @{}
        foreach ($spec in @(Get-NRFirewallFilterSpecs)) {
            $type = switch ($spec.JsonName) {
                'address' { 'Address' }
                'application' { 'Application' }
                'port' { 'Port' }
                'service' { 'Service' }
                'interface' { 'Interface' }
                'interfaceType' { 'InterfaceType' }
                'security' { 'Security' }
            }
            $filter = New-NRFixtureFirewallFilter -Type $type -InstanceId 'Rule-A'
            $nativeIndexes[$spec.JsonName] = @{ 'Rule-A' = $filter }
            Mock $spec.Cmdlet -ModuleName PSNetRules { throw 'Captured source should prevent provider re-query.' }
        }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { throw 'Captured source should prevent rule re-query.' }
        $source = [pscustomobject]@{ PolicyStore = 'PersistentStore'; Rules = @($rule); FilterIndexes = $nativeIndexes }

        $inventory = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore -CaptureSource $source
        $inventory.RuleCount | Should-Be 1
        $inventory.Entries[0].IsComplete | Should-Be $true
        $inventory.Entries[0].Fields['Rule.Enabled'].Value | Should-Be 'True'
        $inventory.Entries[0].Fields['Address.RemoteAddress'].Value | Should-BeCollection @('Any')
        $inventory.Entries[0].Fields['Security.Authentication'].Value | Should-Be 'NotRequired'
        Should-Invoke Get-NetFirewallRule -ModuleName PSNetRules -Times 0 -Exactly
        foreach ($spec in @(Get-NRFirewallFilterSpecs)) {
            Should-Invoke $spec.Cmdlet -ModuleName PSNetRules -Times 0 -Exactly
        }
    }

    It 'updates progress while projecting comparison entries' {
        $source = [pscustomobject]@{
            PolicyStore = 'PersistentStore'
            Rules = @(
                [pscustomobject]@{ Name = 'Rule-A' },
                [pscustomobject]@{ Name = 'Rule-B' },
                [pscustomobject]@{ Name = 'Rule-C' }
            )
            FilterIndexes = @{}
            Warnings = @()
        }
        Mock Get-NRFirewallRuleComparisonSource -ModuleName PSNetRules { $source }
        Mock ConvertTo-NRFirewallRuleComparisonEntry -ModuleName PSNetRules {
            [pscustomobject]@{ Name = $Rule.Name; IsComplete = $true; Fields = @{} }
        }
        Mock Write-Progress -ModuleName PSNetRules {}

        $inventory = Invoke-NRPrivateFunction -Name Get-NRFirewallRuleComparisonInventory -Parameters @{
            PolicyStore = 'PersistentStore'
            ShowProgress = $true
        }
        $inventory.RuleCount | Should-Be 3
        $inventory.Entries.Count | Should-Be 3
        Should-Invoke ConvertTo-NRFirewallRuleComparisonEntry -ModuleName PSNetRules -Times 3 -Exactly
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 5 -Exactly -ParameterFilter {
            $Id -eq 1 -and $ParentId -eq 0
        }
    }

    It 'reports an empty comparison inventory without leaving progress active' {
        Mock Write-Progress -ModuleName PSNetRules {}

        Invoke-NRPrivateFunction -Name Write-NRFirewallRuleComparisonProgress -Parameters @{
            PolicyStore = 'SystemDefaults'
            Completed = 0
            Total = 0
        }
        Invoke-NRPrivateFunction -Name Write-NRFirewallRuleComparisonProgress -Parameters @{
            PolicyStore = 'SystemDefaults'
            Completed = 0
            Total = 0
            Complete = $true
        }

        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Status -eq 'No rules to project.' -and $PercentComplete -eq 100
        }
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Id -eq 1 -and $Completed
        }
    }

    It 'initializes an empty comparison index for an omitted captured filter collection' {
        $indexes = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonFilterIndexesFromCapture -Parameters @{
            NativeFilterIndexes = @{ address = @{} }
        }
        $indexes.Count | Should-Be 7
        $indexes.Address.Count | Should-Be 0
        $indexes.Security.Count | Should-Be 0
    }

    It 'rejects a captured comparison source from a different PolicyStore' {
        $source = [pscustomobject]@{ PolicyStore = 'SystemDefaults'; Rules = @(); FilterIndexes = @{} }
        { Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore -CaptureSource $source } |
            Should-Throw -ExceptionMessage '*does not match requested PolicyStore*'
    }

    It 'captures full rule and seven-filter comparison properties from bulk indexes' {
        $rule = New-NRFixtureFirewallRuleObject -Properties ([ordered]@{
            Name = 'Rule-A'; InstanceID = 'rule-a-id'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'
        })
        $addressFilter = New-NRFixtureFirewallFilter -Type Address -InstanceId 'rule-a-id' -Properties @{ RemoteAddress = @('LocalSubnet') }
        $applicationFilter = New-NRFixtureFirewallFilter -Type Application -InstanceId 'rule-a-id' -Properties @{ Program = 'C:\app.exe'; Package = $null }
        $portFilter = New-NRFixtureFirewallFilter -Type Port -InstanceId 'rule-a-id' -Properties @{ LocalPort = @('443') }
        $serviceFilter = New-NRFixtureFirewallFilter -Type Service -InstanceId 'rule-a-id' -Properties @{ Service = 'ExampleSvc' }
        $interfaceFilter = New-NRFixtureFirewallFilter -Type Interface -InstanceId 'rule-a-id' -Properties @{ InterfaceAlias = @('Ethernet') }
        $interfaceTypeFilter = New-NRFixtureFirewallFilter -Type InterfaceType -InstanceId 'rule-a-id' -Properties @{ InterfaceType = @('Lan') }
        $securityFilter = New-NRFixtureFirewallFilter -Type Security -InstanceId 'rule-a-id' -Properties @{ Authentication = 'NotRequired'; Encryption = 'NotRequired' }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @($rule) }
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules { @($addressFilter) }
        Mock Get-NetFirewallApplicationFilter -ModuleName PSNetRules { @($applicationFilter) }
        Mock Get-NetFirewallPortFilter -ModuleName PSNetRules { @($portFilter) }
        Mock Get-NetFirewallServiceFilter -ModuleName PSNetRules { @($serviceFilter) }
        Mock Get-NetFirewallInterfaceFilter -ModuleName PSNetRules { @($interfaceFilter) }
        Mock Get-NetFirewallInterfaceTypeFilter -ModuleName PSNetRules { @($interfaceTypeFilter) }
        Mock Get-NetFirewallSecurityFilter -ModuleName PSNetRules { @($securityFilter) }
        Mock Write-Progress -ModuleName PSNetRules {}

        $inventory = Invoke-NRPrivateFunction -Name Get-NRFirewallRuleComparisonInventory -Parameters @{
            PolicyStore = 'PersistentStore'
            ShowProgress = $true
        }
        $inventory.RuleCount | Should-Be 1
        $inventory.Entries.Count | Should-Be 1
        $entry = $inventory.Entries[0]
        $entry.IsComplete | Should-Be $true
        $entry.Fields['Rule.Enabled'].Value | Should-Be 'True'
        $entry.Fields['Rule.Enabled'].PSObject.Properties['Canonical'] | Should-Be $null
        $entry.Fields['Address.RemoteAddress'].Value | Should-BeCollection @('LocalSubnet')
        $entry.Fields['Application.Program'].Value | Should-Be 'C:\app.exe'
        $entry.Fields['Port.LocalPort'].Value | Should-BeCollection @('443')
        $entry.Fields['Service.Service'].Value | Should-Be 'ExampleSvc'
        $entry.Fields['Interface.InterfaceAlias'].Value | Should-BeCollection @('Ethernet')
        $entry.Fields['InterfaceType.InterfaceType'].Value | Should-BeCollection @('Lan')
        $entry.Fields['Security.Authentication'].Value | Should-Be 'NotRequired'
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 3 -Exactly -ParameterFilter {
            $Id -eq 1 -and $ParentId -eq 0
        }
    }

    It 'exposes the program under the record name when the application filter uses the CIM AppPath property' {
        $cimRule = New-NRFixtureFirewallRuleObject -Properties ([ordered]@{
            Name = 'Rule-Cim'; InstanceID = 'rule-cim-id'; Enabled = 'True'; Direction = 'Outbound'; Action = 'Allow'
        })
        $bothRule = New-NRFixtureFirewallRuleObject -Properties ([ordered]@{
            Name = 'Rule-Both'; InstanceID = 'rule-both-id'; Enabled = 'True'; Direction = 'Outbound'; Action = 'Allow'
        })
        $cimAddress = New-NRFixtureFirewallFilter -Type Address -InstanceId 'rule-cim-id' -Properties @{ RemoteAddress = @('Any') }
        $bothAddress = New-NRFixtureFirewallFilter -Type Address -InstanceId 'rule-both-id' -Properties @{ RemoteAddress = @('Any') }
        $cimApplication = [pscustomobject]@{ InstanceID = 'rule-cim-id'; AppPath = 'C:\cim\app.exe'; Package = $null }
        $bothApplication = [pscustomobject]@{ InstanceID = 'rule-both-id'; AppPath = 'C:\cim\alias.exe'; Program = 'C:\record\app.exe'; Package = $null }
        $cimPort = [pscustomobject]@{ InstanceID = 'rule-cim-id'; Protocol = 'UDP'; LocalPort = @('5353'); RemotePort = @('Any'); IcmpType = @(); DynamicTransport = 'Any' }
        $bothPort = New-NRFixtureFirewallFilter -Type Port -InstanceId 'rule-both-id' -Properties @{ LocalPort = @('Any') }
        $cimService = [pscustomobject]@{ InstanceID = 'rule-cim-id'; ServiceName = 'ExampleSvc' }
        $bothService = New-NRFixtureFirewallFilter -Type Service -InstanceId 'rule-both-id' -Properties @{ Service = 'Any' }
        $cimInterface = New-NRFixtureFirewallFilter -Type Interface -InstanceId 'rule-cim-id' -Properties @{ InterfaceAlias = @('Any') }
        $bothInterface = New-NRFixtureFirewallFilter -Type Interface -InstanceId 'rule-both-id' -Properties @{ InterfaceAlias = @('Any') }
        $cimInterfaceType = New-NRFixtureFirewallFilter -Type InterfaceType -InstanceId 'rule-cim-id' -Properties @{ InterfaceType = 'Any' }
        $bothInterfaceType = New-NRFixtureFirewallFilter -Type InterfaceType -InstanceId 'rule-both-id' -Properties @{ InterfaceType = 'Any' }
        $cimSecurity = [pscustomobject]@{ InstanceID = 'rule-cim-id'; LocalUsers = 'O:LSD:(A;;CC;;;S-1-5-21-1001)'; RemoteUsers = 'Any'; RemoteMachines = 'Any'; Authentication = 'NotRequired'; Encryption = 'NotRequired'; OverrideBlockRules = $false }
        $bothSecurity = New-NRFixtureFirewallFilter -Type Security -InstanceId 'rule-both-id' -Properties @{ Authentication = 'NotRequired' }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @($cimRule, $bothRule) }
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules { @($cimAddress, $bothAddress) }
        Mock Get-NetFirewallApplicationFilter -ModuleName PSNetRules { @($cimApplication, $bothApplication) }
        Mock Get-NetFirewallPortFilter -ModuleName PSNetRules { @($cimPort, $bothPort) }
        Mock Get-NetFirewallServiceFilter -ModuleName PSNetRules { @($cimService, $bothService) }
        Mock Get-NetFirewallInterfaceFilter -ModuleName PSNetRules { @($cimInterface, $bothInterface) }
        Mock Get-NetFirewallInterfaceTypeFilter -ModuleName PSNetRules { @($cimInterfaceType, $bothInterfaceType) }
        Mock Get-NetFirewallSecurityFilter -ModuleName PSNetRules { @($cimSecurity, $bothSecurity) }
        Mock Write-Progress -ModuleName PSNetRules {}

        $inventory = Invoke-NRPrivateFunction -Name Get-NRFirewallRuleComparisonInventory -Parameters @{
            PolicyStore = 'PersistentStore'
        }
        $inventory.Entries.Count | Should-Be 2
        $cimEntry = @($inventory.Entries | Where-Object { $_.Name -eq 'Rule-Cim' })[0]
        $cimEntry.Fields['Application.AppPath'].Value | Should-Be 'C:\cim\app.exe'
        $cimEntry.Fields['Application.Program'].Value | Should-Be 'C:\cim\app.exe'
        $cimEntry.Fields['Port.DynamicTransport'].Value | Should-Be 'Any'
        $cimEntry.Fields['Port.DynamicTarget'].Value | Should-Be 'Any'
        $cimEntry.Fields['Service.ServiceName'].Value | Should-Be 'ExampleSvc'
        $cimEntry.Fields['Service.Service'].Value | Should-Be 'ExampleSvc'
        $cimEntry.Fields['Security.LocalUsers'].Value | Should-Be 'O:LSD:(A;;CC;;;S-1-5-21-1001)'
        $cimEntry.Fields['Security.LocalUser'].Value | Should-Be 'O:LSD:(A;;CC;;;S-1-5-21-1001)'
        $cimEntry.Fields['Security.RemoteUser'].Value | Should-Be 'Any'
        $cimEntry.Fields['Security.RemoteMachine'].Value | Should-Be 'Any'
        $bothEntry = @($inventory.Entries | Where-Object { $_.Name -eq 'Rule-Both' })[0]
        $bothEntry.Fields['Application.Program'].Value | Should-Be 'C:\record\app.exe'
    }

    It 'uses associated-rule fallback when a bulk filter query fails' {
        $rule = New-NRFixtureFirewallRule -Name 'Rule-A' -InstanceId 'rule-a-id'
        $address = [pscustomobject]@{ InstanceID = 'rule-a-id'; LocalAddress = @('Any'); RemoteAddress = @('Any') }
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @($rule) }
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules { throw 'bulk address query failed' }
        Mock Get-NRAssociatedComparisonFilter -ModuleName PSNetRules { @($address) }
        Mock Get-NetFirewallApplicationFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; Program = 'Any' }) }
        Mock Get-NetFirewallPortFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; Protocol = 'TCP' }) }
        Mock Get-NetFirewallServiceFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; Service = 'Any' }) }
        Mock Get-NetFirewallInterfaceFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; InterfaceAlias = @('Any') }) }
        Mock Get-NetFirewallInterfaceTypeFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; InterfaceType = 'Any' }) }
        Mock Get-NetFirewallSecurityFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; Authentication = 'NotRequired' }) }

        $inventory = Invoke-NRPrivateFunction -Name Get-NRFirewallRuleComparisonInventory -Parameters @{ PolicyStore = 'PersistentStore' }
        $inventory.Entries[0].IsComplete | Should-Be $true
        $inventory.BulkFilterWarnings.Count | Should-Be 1
        $inventory.BulkFilterWarnings[0].Filter | Should-Be 'Address'
        Should-Invoke Get-NetFirewallAddressFilter -ModuleName PSNetRules -Times 1 -Exactly
        Should-Invoke Get-NRAssociatedComparisonFilter -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'marks a rule incomplete when both bulk and associated filter queries fail' {
        $rule = New-NRFixtureFirewallRule -Name 'Rule-A' -InstanceId 'rule-a-id'
        Mock Get-NetFirewallRule -ModuleName PSNetRules { @($rule) }
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules {
            throw 'address query unavailable'
        }
        Mock Get-NRAssociatedComparisonFilter -ModuleName PSNetRules {
            throw 'address query unavailable'
        }
        Mock Get-NetFirewallApplicationFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; Program = 'Any' }) }
        Mock Get-NetFirewallPortFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; Protocol = 'TCP' }) }
        Mock Get-NetFirewallServiceFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; Service = 'Any' }) }
        Mock Get-NetFirewallInterfaceFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; InterfaceAlias = @('Any') }) }
        Mock Get-NetFirewallInterfaceTypeFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; InterfaceType = 'Any' }) }
        Mock Get-NetFirewallSecurityFilter -ModuleName PSNetRules { @([pscustomobject]@{ InstanceID = 'rule-a-id'; Authentication = 'NotRequired' }) }

        $inventory = Invoke-NRPrivateFunction -Name Get-NRFirewallRuleComparisonInventory -Parameters @{ PolicyStore = 'PersistentStore' }
        $inventory.Entries[0].IsComplete | Should-Be $false
        ($inventory.Entries[0].MissingFilters -contains 'Address') | Should-Be $true
        $inventory.Entries[0].FilterIssues[0].Detail | Should-MatchString 'address query unavailable'
    }

    It 'reuses PersistentStore capture source while separately querying SystemDefaults' {
        $configuration = New-NRFixtureConfiguration
        $source = [pscustomobject]@{
            PolicyStore = 'PersistentStore'
            Rules = @()
            FilterIndexes = @{}
        }
        foreach ($spec in @(Get-NRFirewallFilterSpecs)) { $source.FilterIndexes[$spec.JsonName] = @{} }
        $captureState = [pscustomobject]@{ Configuration = $configuration; ComparisonSource = $source }
        $persistent = [pscustomobject]@{
            PolicyStore = 'PersistentStore'; RuleCount = 1
            Entries = @([pscustomobject]@{ Name = 'AllowHttps'; IsComplete = $true; Fields = @{} })
            BulkFilterWarnings = @()
        }
        $defaults = [pscustomobject]@{ PolicyStore = 'SystemDefaults'; RuleCount = 0; Entries = @(); BulkFilterWarnings = @() }
        Mock Get-NRCurrentState -ModuleName PSNetRules { $captureState }
        Mock Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules {
            if ($PolicyStore -eq 'PersistentStore') {
                $CaptureSource.PolicyStore | Should-Be 'PersistentStore'
                return $persistent
            }
            return $defaults
        }
        Mock Write-Progress -ModuleName PSNetRules {}

        $snapshot = New-NRCaptureSnapshot -StatePath (Join-Path $TestDrive 'source-reuse-state.json')
        $snapshot.comparison.persistentStore.RuleCount | Should-Be 1
        Should-Invoke Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $PolicyStore -eq 'PersistentStore' -and $null -ne $CaptureSource -and $ShowProgress
        }
        Should-Invoke Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $PolicyStore -eq 'SystemDefaults' -and $null -eq $CaptureSource -and $ShowProgress
        }
    }

    It 'builds a snapshot when every compared rule has all required filters' {
        $configuration = New-NRFixtureConfiguration
        $persistent = [pscustomobject]@{
            PolicyStore = 'PersistentStore'; RuleCount = 1
            Entries = @([pscustomobject]@{ Name = 'AllowHttps'; IsComplete = $true; Fields = @{} })
            BulkFilterWarnings = @()
        }
        $defaults = [pscustomobject]@{
            PolicyStore = 'SystemDefaults'; RuleCount = 0; Entries = @(); BulkFilterWarnings = @()
        }
        Mock Get-NRCurrentState -ModuleName PSNetRules { $configuration }
        Mock Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules {
            if ($PolicyStore -eq 'PersistentStore') { return $persistent }
            return $defaults
        }
        Mock Write-Progress -ModuleName PSNetRules {}

        $snapshot = New-NRCaptureSnapshot -StatePath (Join-Path $TestDrive 'snapshot-state.json')
        $snapshot.schemaVersion | Should-Be 1
        $snapshot.configuration.firewallRules.Count | Should-Be 1
        $snapshot.comparison.persistentStore.RuleCount | Should-Be 1
        $snapshot.comparison.systemDefaults.RuleCount | Should-Be 0
    }

    It 'rejects an incomplete comparison inventory rather than misclassifying rules' {
        $configuration = New-NRFixtureConfiguration
        $persistent = [pscustomobject]@{
            PolicyStore = 'PersistentStore'; RuleCount = 1
            Entries = @([pscustomobject]@{ Name = 'AllowHttps'; IsComplete = $false; Fields = @{} })
            BulkFilterWarnings = @()
        }
        $defaults = [pscustomobject]@{ PolicyStore = 'SystemDefaults'; RuleCount = 0; Entries = @(); BulkFilterWarnings = @() }
        Mock Get-NRCurrentState -ModuleName PSNetRules { $configuration }
        Mock Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules {
            if ($PolicyStore -eq 'PersistentStore') { return $persistent }
            return $defaults
        }
        Mock Write-Progress -ModuleName PSNetRules {}

        { New-NRCaptureSnapshot -StatePath (Join-Path $TestDrive 'incomplete-state.json') } |
            Should-Throw -ExceptionMessage '*Cannot create a comparable snapshot*'
    }
}

Describe 'PSNetRules Firewall rule classification states' {
    It 'classifies managed, unmanaged, modified, missing, and deleted rules independently of default matching' {
        $currentRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'InSync'),
            (New-NRFixtureFirewallRuleRecord -Name 'Modified' -LocalPort '8443'),
            (New-NRFixtureFirewallRuleRecord -Name 'DefaultExcluded'),
            (New-NRFixtureFirewallRuleRecord -Name 'NewCandidate'),
            (New-NRFixtureFirewallRuleRecord -Name 'DeletePending'),
            (New-NRFixtureFirewallRuleRecord -Name 'ExcludedRule')
        )
        $desiredRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'InSync'),
            (New-NRFixtureFirewallRuleRecord -Name 'Modified' -LocalPort '443'),
            (New-NRFixtureFirewallRuleRecord -Name 'Missing')
        )
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration)
        $snapshot.configuration.firewallRules = $currentRules
        $fieldsExact = @{ 'Rule.Enabled' = [pscustomobject]@{ Value = 'True' } }
        $fieldsDifferent = @{ 'Rule.Enabled' = [pscustomobject]@{ Value = 'False' } }
        $snapshot.comparison.persistentStore.Entries = @(
            foreach ($name in @('InSync', 'Modified', 'DefaultExcluded', 'NewCandidate', 'DeletePending')) {
                [pscustomobject]@{ Name = $name; IsComplete = $true; Fields = $fieldsExact }
            }
        )
        $snapshot.comparison.systemDefaults.Entries = @(
            [pscustomobject]@{ Name = 'InSync'; IsComplete = $true; Fields = $fieldsExact },
            [pscustomobject]@{ Name = 'Modified'; IsComplete = $true; Fields = $fieldsDifferent },
            [pscustomobject]@{ Name = 'DefaultExcluded'; IsComplete = $true; Fields = $fieldsExact }
        )
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = $desiredRules
        $desired.excludedFirewallRules = @('ExcludedRule', 'ExcludedMissingRule')
        $state = [pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('InSync', 'Modified', 'Missing', 'DeletePending', 'DeleteComplete', 'ExcludedMissingRule') }

        $results = @(Get-NRFirewallRuleClassification -Snapshot $snapshot -Desired $desired -State $state)
        (@($results | Where-Object Name -eq 'InSync')[0]).Status | Should-Be 'InSync'
        (@($results | Where-Object Name -eq 'InSync')[0]).SystemDefaults | Should-Be 'ExactMatch'
        (@($results | Where-Object Name -eq 'Modified')[0]).Status | Should-Be 'Modified'
        (@($results | Where-Object Name -eq 'Missing')[0]).Status | Should-Be 'Missing'
        (@($results | Where-Object Name -eq 'DeletePending')[0]).Status | Should-Be 'DeletePending'
        (@($results | Where-Object Name -eq 'DeleteComplete')[0]).Status | Should-Be 'DeleteComplete'
        (@($results | Where-Object Name -eq 'DefaultExcluded')[0]).Status | Should-Be 'DefaultExcluded'
        (@($results | Where-Object Name -eq 'NewCandidate')[0]).Status | Should-Be 'NewCandidate'
        (@($results | Where-Object Name -eq 'ExcludedRule')[0]).Status | Should-Be 'Excluded'
        (@($results | Where-Object Name -eq 'ExcludedRule')[0]).Management | Should-Be 'Excluded'
        (@($results | Where-Object Name -eq 'ExcludedMissingRule')[0]).Status | Should-Be 'ExcludedMissing'
        @($results | Where-Object Status -eq 'DeleteComplete' | Where-Object Name -eq 'ExcludedMissingRule').Count | Should-Be 0
    }

    It 'returns distinct default comparison states for absent and incomplete inventories' {
        $persistent = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $false; Fields = @{} } }
        $defaults = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $true; Fields = @{} } }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) | Should-Be 'Inconclusive'
        (Get-NRDefaultRuleStatus -Name 'Rule-B' -PersistentComparisonByName @{} -SystemDefaultsByName $defaults) | Should-Be 'NotFound'
        $persistent['Rule-A'] = [pscustomobject]@{ IsComplete = $true; Fields = @{'Rule.Enabled' = [pscustomobject]@{ Value = $true }} }
        $defaults['Rule-A'] = [pscustomobject]@{ IsComplete = $true; Fields = @{'Rule.Enabled' = [pscustomobject]@{ Value = $false }} }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) | Should-Be 'Mismatch'
    }
}

Describe 'PSNetRules Firewall rule rename detection' {
    It 'compares all Firewall rule properties except the two Name fields using existing value semantics' {
        $before = New-NRFixtureFirewallRuleRecord -Name 'Old-Rule' -DisplayName 'Application Firewall'
        $after = New-NRFixtureFirewallRuleRecord -Name 'New-Rule' -DisplayName 'Application Firewall'
        $before.filters.address.LocalAddress = @('10.0.0.1', '10.0.0.2')
        $after.filters.address.LocalAddress = @('10.0.0.2', '10.0.0.1')

        (Invoke-NRPrivateFunction -Name Test-NRFirewallRuleRenameEquivalent -Parameters @{ Before = $before; After = $after }) | Should-Be $true

        $after.filters.port.LocalPort = @('8443')
        (Invoke-NRPrivateFunction -Name Test-NRFirewallRuleRenameEquivalent -Parameters @{ Before = $before; After = $after }) | Should-Be $false
        $after.filters.port.LocalPort = @('443')
        $after.rule.Description = 'different case-sensitive value'
        (Invoke-NRPrivateFunction -Name Test-NRFirewallRuleRenameEquivalent -Parameters @{ Before = $before; After = $after }) | Should-Be $false
    }

    It 'classifies a unique name-only replacement as one Rename instead of Missing and NewCandidate' {
        $oldRule = New-NRFixtureFirewallRuleRecord -Name 'Old-Application-Rule' -DisplayName 'Application Firewall'
        $newRule = New-NRFixtureFirewallRuleRecord -Name 'New-Application-Rule' -DisplayName 'Application Firewall'
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @($newRule)
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @($oldRule)
        $state = [pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Old-Application-Rule') }

        $results = @(Get-NRFirewallRuleClassification -Snapshot $snapshot -Desired $desired -State $state)
        $results.Count | Should-Be 1
        $results[0].Status | Should-Be 'Rename'
        $results[0].OldName | Should-Be 'Old-Application-Rule'
        $results[0].NewName | Should-Be 'New-Application-Rule'
        $results[0].Management | Should-Be 'Managed'
        $newSelection = @(Invoke-NRPrivateFunction -Name Get-NRAdoptSelection -Parameters @{
            New = $true; Update = $false; Names = @(); Classifications = $results
            CurrentByName = @{ 'New-Application-Rule' = $newRule }; DesiredByName = @{ 'Old-Application-Rule' = $oldRule }
            ManagedNames = @('Old-Application-Rule')
        })
        $newSelection.Count | Should-Be 0
    }

    It 'does not infer a Rename when more than one old rule can match the same candidate' {
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'New-Rule' -DisplayName 'Same Application')
        )
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'Old-Rule-A' -DisplayName 'Same Application'),
            (New-NRFixtureFirewallRuleRecord -Name 'Old-Rule-B' -DisplayName 'Same Application')
        )
        $state = [pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Old-Rule-A', 'Old-Rule-B') }

        $results = @(Get-NRFirewallRuleClassification -Snapshot $snapshot -Desired $desired -State $state)
        @($results | Where-Object Status -eq 'Rename').Count | Should-Be 0
        @($results | Where-Object Status -eq 'Missing').Count | Should-Be 2
        @($results | Where-Object Status -eq 'NewCandidate').Count | Should-Be 1
    }

    It 'does not infer a Rename when one missing rule can match multiple candidates' {
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'New-Rule-A' -DisplayName 'Same Application'),
            (New-NRFixtureFirewallRuleRecord -Name 'New-Rule-B' -DisplayName 'Same Application')
        )
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Old-Rule' -DisplayName 'Same Application'))
        $state = [pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Old-Rule') }

        $results = @(Get-NRFirewallRuleClassification -Snapshot $snapshot -Desired $desired -State $state)
        @($results | Where-Object Status -eq 'Rename').Count | Should-Be 0
        @($results | Where-Object Status -eq 'Missing').Count | Should-Be 1
        @($results | Where-Object Status -eq 'NewCandidate').Count | Should-Be 2
    }

    It 'renders Rename and supports filtering the Rename status' {
        $rename = [pscustomobject]@{
            Name = 'Old-Rule'; OldName = 'Old-Rule'; NewName = 'New-Rule'; Status = 'Rename'
            Management = 'Managed'; SystemDefaults = 'NotFound'; Details = @()
            DisplayName = 'Application Firewall'; Group = ''; Program = $null; Package = $null; Service = $null
        }
        $allOutput = @(Format-NRFirewallRuleClassification -Results @($rename)) -join [Environment]::NewLine
        $filteredOutput = @(Format-NRFirewallRuleClassification -Results @($rename) -Status Rename) -join [Environment]::NewLine
        $allOutput | Should-MatchString 'Rename'
        $allOutput | Should-MatchString '\[Rename\] Old-Rule -> New-Rule'
        $filteredOutput | Should-MatchString '\[Rename\] Old-Rule -> New-Rule'
    }
}

Describe 'PSNetRules generated change script branches' {
    It 'generates create, update, recreate, delete, profile, and NRPT commands from the Snapshot' {
        $path = Join-Path $TestDrive 'generate-all-operations.json'
        $desired = New-NRFixtureConfiguration
        $updateDesired = New-NRFixtureFirewallRuleRecord -Name 'UpdateRule'
        $updateDesired.rule.Description = 'Updated description'
        $recreateDesired = New-NRFixtureFirewallRuleRecord -Name 'RecreateRule'
        $recreateDesired.rule.Group = 'Updated group'
        $desired.firewallRules = @($updateDesired, $recreateDesired, (New-NRFixtureFirewallRuleRecord -Name 'NewRule'))
        $desired.firewallProfiles.Private.Enabled = 'False'
        $desired.nrptRules = @(
            (New-NRFixtureNrptRuleRecord -Id 'corp-dns' -Server '10.10.0.54'),
            (New-NRFixtureNrptRuleRecord -Id 'new-dns' -Server '10.10.0.55')
        )
        Write-NRJsonFile -Path $path -InputObject $desired

        $captured = New-NRFixtureConfiguration
        $captured.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'UpdateRule'),
            (New-NRFixtureFirewallRuleRecord -Name 'RecreateRule'),
            (New-NRFixtureFirewallRuleRecord -Name 'DeleteRule')
        )
        $captured.nrptRules = @(
            (New-NRFixtureNrptRuleRecord -Id 'corp-dns' -Server '10.10.0.53'),
            (New-NRFixtureNrptRuleRecord -Id 'gone-dns' -Server '10.10.0.56')
        )
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{
            nrptRules = @{
                'corp-dns' = '{11111111-1111-1111-1111-111111111111}'
                'gone-dns' = '{22222222-2222-2222-2222-222222222222}'
            }
            managedFirewallRules = @('UpdateRule', 'RecreateRule', 'DeleteRule')
        })
        $outputPath = Join-Path $TestDrive 'generated-all-operations.ps1'

        $result = @(Invoke-NRGenerate -Path $path -OutputPath $outputPath) -join [Environment]::NewLine
        $result | Should-MatchString 'Generated:'
        $generated = Get-Content -LiteralPath $outputPath -Raw
        $generated | Should-MatchString 'Set-NetFirewallRule'
        $generated | Should-MatchString 'New-NetFirewallRule'
        $generated | Should-MatchString 'Remove-NetFirewallRule'
        $generated | Should-MatchString 'Set-NetFirewallProfile'
        $generated | Should-MatchString 'Remove-DnsClientNrptRule'
        $generated | Should-MatchString 'Add-DnsClientNrptRule'
        $generated | Should-MatchString 'Save-NRGeneratedNrptState'
        $generated | Should-NotMatchString 'Read-NRStateFile'
        $generated | Should-NotMatchString 'Write-NRStateFile'
        $generated | Should-MatchString 'corp-dns'
        $generated | Should-MatchString 'gone-dns'
        $generated | Should-MatchString 'new-dns'
    }

    It 'backs up only existing files and preserves their contents' {
        $configurationPath = Join-Path $TestDrive 'backup-source.json'
        $statePath = Join-Path $TestDrive 'backup-source.state.json'
        Set-Content -LiteralPath $configurationPath -Value '{"configuration":true}' -NoNewline
        Set-Content -LiteralPath $statePath -Value '{"state":true}' -NoNewline

        $backups = @(New-NRFileBackup -Paths @($configurationPath, $statePath, (Join-Path $TestDrive 'missing.json')) `
            -ConfigurationPath $configurationPath -Suffix 'unit')

        $backups.Count | Should-Be 2
        (Get-Content -LiteralPath $backups[0] -Raw) | Should-Be '{"configuration":true}'
        (Get-Content -LiteralPath $backups[1] -Raw) | Should-Be '{"state":true}'
    }

    It 'rejects a missing, malformed, or incomplete capture Snapshot' {
        $path = Join-Path $TestDrive 'missing.snapshot.json'
        { Read-NRSnapshot -Path $path } | Should-Throw -ExceptionMessage '*Capture snapshot not found*'
        [System.IO.File]::WriteAllText($path, '{bad json')
        { Read-NRSnapshot -Path $path } | Should-Throw -ExceptionMessage '*Unable to parse snapshot file*'
        [System.IO.File]::WriteAllText($path, '{"schemaVersion":1,"configuration":{},"comparison":null}')
        { Read-NRSnapshot -Path $path } | Should-Throw -ExceptionMessage '*Invalid capture snapshot*'
    }

    It 'accepts the current Snapshot schema version and rejects other versions' {
        $path = Join-Path $TestDrive 'snapshot-schema-version.json'
        [System.IO.File]::WriteAllText($path, '{"schemaVersion":1,"configuration":{},"comparison":{}}')
        (Read-NRSnapshot -Path $path).schemaVersion | Should-Be 1
        foreach ($version in @(2, 3)) {
            $json = '{{"schemaVersion":{0},"configuration":{{}},"comparison":{{}}}}' -f $version
            [System.IO.File]::WriteAllText($path, $json)
            { Read-NRSnapshot -Path $path } | Should-Throw -ExceptionMessage '*Invalid capture snapshot*'
        }
    }

}

Describe 'PSNetRules top-level command-line entry point' {
    It 'rejects Rename outside adopt' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('diff', '-Rename')
        $result.ExitCode | Should-Be 1
        $result.StandardError | Should-MatchString '-Rename are supported only by adopt'
    }

    It 'routes Rename status and adoption through the command-line entry point' {
        $path = Join-Path $TestDrive 'entrypoint-rename.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Old-Rule' -DisplayName 'Application Rule'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'New-Rule' -DisplayName 'Application Rule'))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Old-Rule') })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText((Get-NRStatePath -Path $path))

        $diff = Invoke-NRRootScriptInChildProcess -Arguments @('diff', '-Path', $path, '-Status', 'Rename')
        Assert-NRChildProcessSuccess -Result $diff -Context 'CLI diff with Rename status'
        $diff.StandardOutput | Should-MatchString '\[Rename\] Old-Rule -> New-Rule'

        $preview = Invoke-NRRootScriptInChildProcess -Arguments @('adopt', '-Path', $path, '-Rename', '-Name', 'Old-Rule', '-WhatIf')
        Assert-NRChildProcessSuccess -Result $preview -Context 'CLI adopt Rename preview'
        $preview.StandardOutput | Should-MatchString 'Old-Rule -> New-Rule'
        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText((Get-NRStatePath -Path $path)) | Should-Be $stateBefore
    }
    It 'displays full command help when no command is supplied, without loading the module' {
        $isolatedDirectory = Join-Path $TestDrive 'help-only'
        New-Item -ItemType Directory -Path $isolatedDirectory -Force | Out-Null
        $isolatedScript = Join-Path $isolatedDirectory 'PSNetRules.ps1'
        Copy-Item -LiteralPath $script:PSNetRulesRootScriptPath -Destination $isolatedScript
        $result = Invoke-NRRootScriptInChildProcess -ScriptPath $isolatedScript
        Assert-NRChildProcessSuccess -Result $result -Context 'CLI help without a command'
        $result.StandardOutput | Should-MatchString 'PSNetRules'
        $result.StandardOutput | Should-MatchString 'capture'
        $result.StandardOutput | Should-MatchString 'generate'
        $result.StandardOutput | Should-MatchString 'unmanage'
        $result.StandardOutput | Should-MatchString 'PARAMETERS'
        ([string]::IsNullOrEmpty($result.StandardError)) | Should-Be $true
    }

    It 'displays help for the standard -? switch' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('-?')
        Assert-NRChildProcessSuccess -Result $result -Context 'CLI help with -?'
        $result.StandardOutput | Should-MatchString 'PSNetRules'
        $result.StandardOutput | Should-MatchString 'capture'
        $result.StandardOutput | Should-MatchString 'unmanage'
        ([string]::IsNullOrEmpty($result.StandardError)) | Should-Be $true
    }

    It 'loads the renamed module and validates a valid configuration through the CLI' {
        $path = Join-Path $TestDrive 'entrypoint-valid-configuration.json'
        Write-TestUtf8JsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-Path', $path)
        Assert-NRChildProcessSuccess -Result $result -Context 'CLI validate'
        $result.Output | Should-MatchString 'Configuration is valid.'
    }

    It 'prints only classification text from the real CLI diff command' {
        $path = Join-Path $TestDrive 'entrypoint-diff.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        $captured = New-NRFixtureConfiguration
        Write-NRJsonFile -Path $path -InputObject $desired
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{
            nrptRules = @{}
            managedFirewallRules = @()
        })

        $result = Invoke-NRRootScriptInChildProcess -Arguments @('diff', '-Path', $path)
        Assert-NRChildProcessSuccess -Result $result -Context 'CLI diff'
        $result.StandardOutput | Should-MatchString '\[NewCandidate\].*AllowHttps'
        $result.StandardOutput | Should-MatchString 'Other managed resources: No changes\.'
        $result.StandardOutput | Should-NotMatchString '"comparison"\s*:'
        $result.StandardOutput | Should-NotMatchString '"Canonical"\s*:'
        ([string]::IsNullOrEmpty($result.StandardError)) | Should-Be $true
    }

    It 'returns a non-zero exit code when CLI validation fails' {
        $path = Join-Path $TestDrive 'entrypoint-invalid-configuration.json'
        [System.IO.File]::WriteAllText($path, '{invalid json')
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-Path', $path)
        $result.ExitCode | Should-Be 1
        $result.StandardError | Should-MatchString 'PSNetRules:'
    }

    It 'rejects WhatIf for commands that do not support preview' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-WhatIf')
        $result.ExitCode | Should-Be 1
        $result.Output | Should-MatchString '-WhatIf is supported only by adopt, unmanage, and generate.'
    }

    It 'rejects Force outside generate' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-Force')
        $result.ExitCode | Should-Be 1
        $result.Output | Should-MatchString '-Force is supported only by generate'
    }

    It 'rejects New and Update outside adopt' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-New')
        $result.ExitCode | Should-Be 1
        $result.Output | Should-MatchString '-New, -Update, and -Rename are supported only by adopt.'
    }

    It 'allows Name only for adopt and unmanage' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-Name', 'Rule-A')
        $result.ExitCode | Should-Be 1
        $result.Output | Should-MatchString '-Name is supported only by adopt and unmanage.'

        $emptyNameResult = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-Name', '')
        $emptyNameResult.ExitCode | Should-Be 1
        $emptyNameResult.Output | Should-MatchString '-Name is supported only by adopt and unmanage.'
    }

    It 'requires Name for the unmanage command' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('unmanage')
        $result.ExitCode | Should-Be 1
        $result.Output | Should-MatchString 'unmanage requires -Name.'
    }

    It 'routes unmanage through the CLI and honors WhatIf without modifying files' {
        $path = Join-Path $TestDrive 'entrypoint-unmanage.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'New-Candidate'))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration)
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)

        $result = Invoke-NRRootScriptInChildProcess -Arguments @('unmanage', '-Path', $path, '-Name', 'New-Candidate', '-WhatIf')

        Assert-NRChildProcessSuccess -Result $result -Context 'CLI unmanage with -WhatIf'
        $result.Output | Should-MatchString 'Rules to unmanage: 1'
        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'backups') -File -ErrorAction SilentlyContinue).Count | Should-Be 0
    }

    It 'rejects OutputPath outside generate' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-OutputPath', 'unused.ps1')
        $result.ExitCode | Should-Be 1
        $result.Output | Should-MatchString '-OutputPath is supported only by generate.'
    }

    It 'rejects Status outside diff' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('validate', '-Status', 'NewCandidate')
        $result.ExitCode | Should-Be 1
        $result.Output | Should-MatchString '-Status is supported only by diff.'
    }
}

Describe 'PSNetRules uncovered branch regression coverage' {

    It 'covers empty scalar and nested canonical sequences deterministically' {
        $empty = Invoke-NRPrivateFunction -Name Get-NRCanonicalSequence -Parameters @{ Value = [object[]]@() }
        @($empty).Count | Should-Be 0

        $values = Invoke-NRPrivateFunction -Name Get-NRCanonicalSequence -Parameters @{ Value = [object[]]@('z', $null, 'a') }
        # Pipeline enumeration drops null output. Index the returned array to
        # verify that the null element remains part of the collection.
        @($values).Count | Should-Be 3
        $values[0] | Should-Be $null
        $values[1] | Should-Be 'a'
        $values[2] | Should-Be 'z'

        $objects = @([pscustomobject]@{ n = 2 }, [pscustomobject]@{ n = 1 })
        $canonical = Invoke-NRPrivateFunction -Name Get-NRCanonicalSequence -Parameters @{ Value = $objects }
        (ConvertTo-NRCanonicalJson $canonical) | Should-Be '[{"n":2},{"n":1}]'
    }

    It 'unwraps one nested array when building a keyed map' {
        $inner = [object[]]@([pscustomobject]@{ id = 'wrapped' })
        $wrapped = ,$inner
        $map = Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{ Items = $wrapped; KeyProperty = 'id' }
        $map.Count | Should-Be 1
        $map.ContainsKey('wrapped') | Should-Be $true
    }

    It 'returns an empty keyed map for an empty collection' {
        $map = Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{ Items = @(); KeyProperty = 'id' }
        $map.Count | Should-Be 0
    }

    It 'rejects empty and duplicate keys when building keyed maps' {
        { Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{ Items = @([pscustomobject]@{ id = '' }); KeyProperty = 'id' } } |
            Should-Throw -ExceptionMessage "*empty 'id'*"
        { Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{
            Items = @([pscustomobject]@{ id = 'duplicate' }, [pscustomobject]@{ id = 'duplicate' }); KeyProperty = 'id'
        } } | Should-Throw -ExceptionMessage "*Duplicate key 'duplicate'*"
    }

    It 'rejects paths that cannot be resolved and paths from non-filesystem providers' {
        { Resolve-NRFilePath -Path '__PSNetRulesMissingDrive__:\missing.json' } |
            Should-Throw -ExceptionMessage '*Unable to resolve path*'
        { Resolve-NRFilePath -Path 'Env:\TEMP' } |
            Should-Throw -ExceptionMessage '*Only FileSystem paths are supported*'
    }

    It 'converts a non-enumerable Firewall property to a one-element string array and skips null array items' {
        $objectValue = [pscustomobject]@{ Child = 'value' }
        $single = Get-NRStringArrayFromObject -Object ([pscustomobject]@{ Value = $objectValue }) -Name Value
        @($single).Count | Should-Be 1
        $single[0] | Should-Be ([string]$objectValue)

        $many = Get-NRStringArrayFromObject -Object ([pscustomobject]@{ Value = @('first', $null, 'last') }) -Name Value
        $many | Should-BeCollection @('first', 'last')
        $numeric = Get-NRStringArrayFromObject -Object ([pscustomobject]@{ Value = 42 }) -Name Value
        $numeric | Should-BeCollection @('42')
        $text = Get-NRStringArrayFromObject -Object ([pscustomobject]@{ Value = 'single' }) -Name Value
        $text | Should-BeCollection @('single')

    }

    It 'rejects an empty rule name and an incomplete filter index' {
        $index = @{}
        { Get-NRFirewallFilterFromIndex -Rule ([pscustomobject]@{ Name = '' }) -FilterIndex $index } |
            Should-Throw -ExceptionMessage '*Name is empty*'
        { Get-NRFirewallFilterFromIndex -Rule ([pscustomobject]@{ Name = 'Rule-A' }) -FilterIndex $index } |
            Should-Throw -ExceptionMessage "*index is missing 'address'*"
        { Get-NRFirewallFilterFromIndex -Rule ([pscustomobject]@{ Name = 'Rule-A' }) -FilterIndex @{ address = @{} } } |
            Should-Throw -ExceptionMessage '*No address filter was returned*'
    }

    It 'rejects NRPT records without a Windows name or logical identifier' {
        { Invoke-NRPrivateFunction -Name ConvertTo-NRNrptRecord -Parameters @{
            Rule = [pscustomobject]@{ Name = '' }; LogicalId = 'logical-id'
        } } | Should-Throw -ExceptionMessage '*empty Windows Name*'
        { Invoke-NRPrivateFunction -Name ConvertTo-NRNrptRecord -Parameters @{
            Rule = [pscustomobject]@{ Name = 'windows-name' }; LogicalId = ''
        } } | Should-Throw -ExceptionMessage '*empty logical id*'
    }

    It 'converts dictionary, sequence, DateTime, Enum, and plain comparison values' {
        $dictionary = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonDictionaryValue -Parameters @{
            Value = [ordered]@{ z = [System.DayOfWeek]::Monday; a = [datetime]'2025-01-02T03:04:05Z' }
        }
        @($dictionary.Keys) | Should-BeCollection @('a', 'z')
        $dictionary.z | Should-Be 'Monday'
        $dictionary.a | Should-Be ([datetime]'2025-01-02T03:04:05Z').ToString('o')

        $list = New-Object System.Collections.ArrayList
        $null = $list.Add('second')
        $null = $list.Add('first')
        $arrayValue = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonPlainValue -Parameters @{ Value = $list }
        $arrayValue | Should-BeCollection @('second', 'first')
        (Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonPlainValue -Parameters @{ Value = [System.DayOfWeek]::Tuesday }) | Should-Be 'Tuesday'
        (Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonPlainValue -Parameters @{ Value = 'plain' }) | Should-Be 'plain'
    }

    It 'ignores bulk comparison filters without InstanceID while indexing identifiable filters' {
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules {
            @(
                [pscustomobject]@{ LocalAddress = @('Any') },
                [pscustomobject]@{ InstanceID = 'rule-a-id'; LocalAddress = @('192.0.2.1') }
            )
        }
        $definition = [pscustomobject]@{ Key = 'Address'; Command = 'Get-NetFirewallAddressFilter' }
        $result = Invoke-NRPrivateFunction -Name Get-NRComparisonFilterIndex -Parameters @{
            PolicyStore = 'PersistentStore'; Definition = $definition
        }
        $result.Warning | Should-Be $null
        $result.Index.Count | Should-Be 1
        $result.Index.ContainsKey('rule-a-id') | Should-Be $true
    }

    It 'records a bulk filter query failure as a warning' {
        Mock Get-NetFirewallAddressFilter -ModuleName PSNetRules { throw 'bulk address query failed' }
        $definition = [pscustomobject]@{ Key = 'Address'; Command = 'Get-NetFirewallAddressFilter' }
        $result = Invoke-NRPrivateFunction -Name Get-NRComparisonFilterIndex -Parameters @{
            PolicyStore = 'PersistentStore'; Definition = $definition
        }
        $result.Index.Count | Should-Be 0
        $result.Warning.Filter | Should-Be 'Address'
        $result.Warning.Detail | Should-MatchString 'bulk address query failed'
    }

    It 'reports zero and multiple associated comparison filters as incomplete issues' {
        $rule = New-NRFixtureFirewallRule -Name 'Rule-A' -InstanceId 'rule-a-id'
        $definition = [pscustomobject]@{ Key = 'Address'; Command = 'Get-NetFirewallAddressFilter' }
        Mock Get-NRAssociatedComparisonFilter -ModuleName PSNetRules { @() }
        $none = Invoke-NRPrivateFunction -Name Get-NRRuleComparisonFilter -Parameters @{
            Rule = $rule; Definition = $definition; Index = @{}
        }
        $none.Filter | Should-Be $null
        $none.Issue.Detail | Should-Be 'No filter object returned by associated-rule query.'
    }

    It 'reports multiple associated comparison filters without selecting an arbitrary result' {
        $rule = New-NRFixtureFirewallRule -Name 'Rule-A' -InstanceId 'rule-a-id'
        $definition = [pscustomobject]@{ Key = 'Address'; Command = 'Get-NetFirewallAddressFilter' }
        Mock Get-NRAssociatedComparisonFilter -ModuleName PSNetRules {
            @(
                [pscustomobject]@{ InstanceID = 'one'; LocalAddress = @('Any') },
                [pscustomobject]@{ InstanceID = 'two'; LocalAddress = @('Any') }
            )
        }
        $multiple = Invoke-NRPrivateFunction -Name Get-NRRuleComparisonFilter -Parameters @{
            Rule = $rule; Definition = $definition; Index = @{}
        }
        $multiple.Filter | Should-Be $null
        $multiple.Issue.Detail | Should-Be 'Associated-rule query returned multiple filter objects.'
    }

    It 'falls back to the associated-rule query when a bulk index has duplicate filters' {
        $rule = New-NRFixtureFirewallRule -Name 'Rule-A' -InstanceId 'rule-a-id'
        $definition = [pscustomobject]@{ Key = 'Address'; Command = 'Get-NetFirewallAddressFilter' }
        $bucket = New-Object System.Collections.ArrayList
        $null = $bucket.Add([pscustomobject]@{ InstanceID = 'rule-a-id'; LocalAddress = @('192.0.2.1') })
        $null = $bucket.Add([pscustomobject]@{ InstanceID = 'rule-a-id'; LocalAddress = @('192.0.2.2') })
        Mock Get-NRAssociatedComparisonFilter -ModuleName PSNetRules {
            [pscustomobject]@{ InstanceID = 'rule-a-id'; LocalAddress = @('192.0.2.3') }
        }
        $result = Invoke-NRPrivateFunction -Name Get-NRRuleComparisonFilter -Parameters @{
            Rule = $rule; Definition = $definition; Index = @{ 'rule-a-id' = $bucket }
        }
        @($result.Filter.LocalAddress) | Should-BeCollection @('192.0.2.3')
        $result.Issue | Should-Be $null
        Should-Invoke Get-NRAssociatedComparisonFilter -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'records an associated-rule filter query exception as an incomplete issue' {
        $rule = New-NRFixtureFirewallRule -Name 'Rule-A' -InstanceId 'rule-a-id'
        $definition = [pscustomobject]@{ Key = 'Address'; Command = 'Get-NetFirewallAddressFilter' }
        Mock Get-NRAssociatedComparisonFilter -ModuleName PSNetRules { throw 'associated address query failed' }
        $result = Invoke-NRPrivateFunction -Name Get-NRRuleComparisonFilter -Parameters @{
            Rule = $rule; Definition = $definition; Index = @{}
        }
        $result.Filter | Should-Be $null
        $result.Issue.Filter | Should-Be 'Address'
        $result.Issue.Detail | Should-MatchString 'associated address query failed'
    }

    It 'invokes the named filter command with the rule through the associated query seam' {
        # The seam is exercised against a fake command defined in the module
        # session state, because the real filter cmdlets only accept a
        # CimInstance rule, which the plain-object fixtures cannot provide.
        $module = $script:NetRulesModule
        & $module {
            function script:Get-NRFakeAssociatedQuery {
                param([object] $AssociatedNetFirewallRule)
                [pscustomobject]@{ InstanceID = [string]$AssociatedNetFirewallRule.InstanceID; LocalAddress = @('192.0.2.9') }
            }
        }
        try {
            $rule = New-NRFixtureFirewallRule -Name 'Rule-A' -InstanceId 'rule-a-id'
            $filters = @(Invoke-NRPrivateFunction -Name Get-NRAssociatedComparisonFilter -Parameters @{
                Command = 'Get-NRFakeAssociatedQuery'; Rule = $rule
            })
            $filters.Count | Should-Be 1
            $filters[0].InstanceID | Should-Be 'rule-a-id'
            @($filters[0].LocalAddress) | Should-BeCollection @('192.0.2.9')
        }
        finally {
            & $module { Remove-Item -Path Function:Get-NRFakeAssociatedQuery -ErrorAction SilentlyContinue }
        }
    }

    It 'returns Inconclusive when the PersistentStore comparison entry is absent and Mismatch when a field is absent' {
        $defaults = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $true; Fields = @{} } }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName @{} -SystemDefaultsByName $defaults) |
            Should-Be 'Inconclusive'
        (Get-NRDefaultRuleStatus -Name 'Rule-Missing' -PersistentComparisonByName @{} -SystemDefaultsByName $defaults) |
            Should-Be 'NotFound'

        $persistent = @{ 'Rule-A' = [pscustomobject]@{
            IsComplete = $true; Fields = @{ 'Rule.Enabled' = [pscustomobject]@{ Value = $true } }
        } }
        $defaults['Rule-A'] = [pscustomobject]@{ IsComplete = $true; Fields = @{} }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) |
            Should-Be 'Mismatch'

        $defaults['Rule-A'] = [pscustomobject]@{ IsComplete = $true; Fields = @{ 'Rule.Enabled' = [pscustomobject]@{ Value = $false } } }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) |
            Should-Be 'Mismatch'


        $defaults['Rule-A'] = [pscustomobject]@{ IsComplete = $true; Fields = @{ 'Rule.Enabled' = [pscustomobject]@{ Value = $true } } }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) |
            Should-Be 'ExactMatch'

        $defaults['Rule-A'] = [pscustomobject]@{ IsComplete = $false; Fields = @{} }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) |
            Should-Be 'Inconclusive'
    }

    It 'rejects capture snapshots when configuration and PersistentStore comparison names differ' {
        $configuration = New-NRFixtureConfiguration
        $configuration.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'ConfigurationOnly'))
        $persistent = [pscustomobject]@{
            Entries = @([pscustomobject]@{ Name = 'ComparisonOnly'; IsComplete = $true })
            RuleCount = 1; BulkFilterWarnings = @()
        }
        $defaults = [pscustomobject]@{ Entries = @(); RuleCount = 0; BulkFilterWarnings = @() }
        Mock Get-NRCurrentState -ModuleName PSNetRules { $configuration }
        Mock Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules {
            if ($PolicyStore -eq 'PersistentStore') { $persistent } else { $defaults }
        }
        Mock Write-Progress -ModuleName PSNetRules {}

        { Invoke-NRPrivateFunction -Name New-NRCaptureSnapshot -Parameters @{ StatePath = (Join-Path $TestDrive 'name-mismatch.state.json') } } |
            Should-Throw -ExceptionMessage '*do not contain the same rule Names*'
    }

    It 'rejects an incomplete PersistentStore comparison inventory' {
        $configuration = New-NRFixtureConfiguration
        $persistentIncomplete = [pscustomobject]@{
            Entries = @([pscustomobject]@{ Name = 'AllowHttps'; IsComplete = $false })
            RuleCount = 1; BulkFilterWarnings = @()
        }
        $defaultsComplete = [pscustomobject]@{ Entries = @(); RuleCount = 0; BulkFilterWarnings = @() }
        Mock Get-NRCurrentState -ModuleName PSNetRules { $configuration }
        Mock Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules {
            if ($PolicyStore -eq 'PersistentStore') { $persistentIncomplete } else { $defaultsComplete }
        }
        Mock Write-Progress -ModuleName PSNetRules {}
        { Invoke-NRPrivateFunction -Name New-NRCaptureSnapshot -Parameters @{ StatePath = (Join-Path $TestDrive 'persistent-incomplete.state.json') } } |
            Should-Throw -ExceptionMessage '*PersistentStore incomplete rules=1*'
    }

    It 'rejects an incomplete SystemDefaults comparison inventory' {
        $configuration = New-NRFixtureConfiguration
        $persistentComplete = [pscustomobject]@{
            Entries = @([pscustomobject]@{ Name = 'AllowHttps'; IsComplete = $true })
            RuleCount = 1; BulkFilterWarnings = @()
        }
        $defaultsIncomplete = [pscustomobject]@{
            Entries = @([pscustomobject]@{ Name = 'Default-A'; IsComplete = $false })
            RuleCount = 1; BulkFilterWarnings = @()
        }
        Mock Get-NRCurrentState -ModuleName PSNetRules { $configuration }
        Mock Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules {
            if ($PolicyStore -eq 'PersistentStore') { $persistentComplete } else { $defaultsIncomplete }
        }
        Mock Write-Progress -ModuleName PSNetRules {}
        { Invoke-NRPrivateFunction -Name New-NRCaptureSnapshot -Parameters @{ StatePath = (Join-Path $TestDrive 'defaults-incomplete.state.json') } } |
            Should-Throw -ExceptionMessage '*SystemDefaults incomplete rules=1*'
    }

    It 'rejects duplicate SystemDefaults rule names in a capture inventory' {
        $configuration = New-NRFixtureConfiguration
        $persistent = [pscustomobject]@{
            Entries = @([pscustomobject]@{ Name = 'AllowHttps'; IsComplete = $true })
            RuleCount = 1; BulkFilterWarnings = @()
        }
        $defaults = [pscustomobject]@{
            Entries = @(
                [pscustomobject]@{ Name = 'Default-Duplicate'; IsComplete = $true },
                [pscustomobject]@{ Name = 'Default-Duplicate'; IsComplete = $true }
            )
            RuleCount = 2; BulkFilterWarnings = @()
        }
        Mock Get-NRCurrentState -ModuleName PSNetRules { $configuration }
        Mock Get-NRFirewallRuleComparisonInventory -ModuleName PSNetRules {
            if ($PolicyStore -eq 'PersistentStore') { $persistent } else { $defaults }
        }
        Mock Write-Progress -ModuleName PSNetRules {}
        { Invoke-NRPrivateFunction -Name New-NRCaptureSnapshot -Parameters @{ StatePath = (Join-Path $TestDrive 'duplicate-defaults.state.json') } } |
            Should-Throw -ExceptionMessage "*Duplicate key 'Default-Duplicate'*"
    }

    It 'returns a scalar unchanged from the object-array normalization helper' {
        $value = [pscustomobject]@{ name = 'single' }
        $result = Invoke-NRPrivateFunction -Name ConvertTo-NRObjectArray -Parameters @{ Value = $value }
        $result.name | Should-Be 'single'
        (Invoke-NRPrivateFunction -Name ConvertTo-NRObjectArray -Parameters @{ Value = $null }) | Should-Be $null
        $nested = ,([object[]]@([object[]]@([pscustomobject]@{ name = 'nested' })))
        $normalized = Invoke-NRPrivateFunction -Name ConvertTo-NRObjectArray -Parameters @{ Value = $nested }
        @($normalized).Count | Should-Be 1
        $normalized[0].name | Should-Be 'nested'
    }

    It 'classifies incomplete default comparisons as ComparisonInconclusive for unmanaged rules' {
        $record = New-NRFixtureFirewallRuleRecord -Name 'Unmanaged'
        $persistent = @{ Unmanaged = [pscustomobject]@{ IsComplete = $false; Fields = @{} } }
        $defaults = @{ Unmanaged = [pscustomobject]@{ IsComplete = $true; Fields = @{} } }
        $result = Invoke-NRPrivateFunction -Name Get-NRUnmanagedFirewallClassifications -Parameters @{
            CurrentByName = @{ Unmanaged = $record }; Managed = @{}
            PersistentByName = $persistent; DefaultsByName = $defaults
        }
        $result[0].Status | Should-Be 'ComparisonInconclusive'
        $result[0].SystemDefaults | Should-Be 'Inconclusive'
    }

    It 'formats meaningful classification fields and omits Any or blank values' {
        $item = [pscustomobject]@{
            Name = 'Rule-A'; DisplayName = 'Friendly Rule'; Status = 'NewCandidate'; SystemDefaults = 'Mismatch'
            Group = 'Application Group'; Program = 'C:\Apps\app.exe'; Package = ''; Service = 'Any'
            Details = @('', 'RemotePort changed')
        }
        $lines = @(Invoke-NRPrivateFunction -Name Format-NRFirewallClassificationItem -Parameters @{ Item = $item })
        ($lines -join "`n") | Should-MatchString 'Rule-A - Friendly Rule'
        ($lines -join "`n") | Should-MatchString 'Group: Application Group'
        ($lines -join "`n") | Should-MatchString 'Program: C:\\Apps\\app.exe'
        ($lines -join "`n") | Should-MatchString 'RemotePort changed'
        ($lines -join "`n") | Should-NotMatchString 'Package:'
        ($lines -join "`n") | Should-NotMatchString 'Service:'
    }

    It 'normalizes a null RemoteDynamicKeywordAddresses property to an empty parameter array' {
        $parameters = @{}
        Invoke-NRPrivateFunction -Name Add-NRFirewallRuleParameters -Parameters @{
            Parameters = $parameters; RuleBody = [pscustomobject]@{ RemoteDynamicKeywordAddresses = $null }
        }
        $parameters.ContainsKey('RemoteDynamicKeywordAddresses') | Should-Be $true
        @($parameters.RemoteDynamicKeywordAddresses).Count | Should-Be 0
    }

    It 'recreates a Firewall rule when a non-mutable Group property changes' {
        $current = New-NRFixtureFirewallRuleRecord -Name 'RecreateRule'
        $desired = New-NRFixtureFirewallRuleRecord -Name 'RecreateRule'
        $current.rule.Group = 'OldGroup'
        $desired.rule.Group = 'NewGroup'
        Mock Remove-NetFirewallRule -ModuleName PSNetRules {}
        Mock New-NRFirewallRule -ModuleName PSNetRules {}

        Invoke-NRFirewallRuleReconcile -Name 'RecreateRule' -DesiredRecord $desired `
            -CurrentRulesByName @{ RecreateRule = [pscustomobject]@{ Name = 'RecreateRule' } } `
            -CurrentSnapshotsByName @{ RecreateRule = $current }

        Should-Invoke Remove-NetFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter {
            $Name -eq 'RecreateRule' -and $PolicyStore -eq 'PersistentStore'
        }
        Should-Invoke New-NRFirewallRule -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Name -eq 'RecreateRule' }
    }

    It 'removes stale NRPT sidecar identifiers even when no current NRPT rules remain' {
        $statePath = Join-Path $TestDrive 'stale-nrpt-map.state.json'
        $stateMap = @{ 'stale-logical-id' = '{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}' }
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = $stateMap; managedFirewallRules = @() })
        Mock Get-DnsClientNrptRule -ModuleName PSNetRules { @() }

        Invoke-NRNrptApply -Desired ([pscustomobject]@{ nrptRules = @() }) -StateMap $stateMap -StatePath $statePath
        $stateMap.ContainsKey('stale-logical-id') | Should-Be $false
        (Read-NRStateFile -Path $statePath).nrptRules.Count | Should-Be 0
    }

    It 'stops the capture timer in finally when snapshot creation fails' {
        Mock Assert-NRAdministrator -ModuleName PSNetRules {}
        Mock New-NRCaptureSnapshot -ModuleName PSNetRules { throw 'capture fixture failure' }
        Mock Write-Progress -ModuleName PSNetRules {}
        { Invoke-NRCapture -Path (Join-Path $TestDrive 'capture-failure.json') } |
            Should-Throw -ExceptionMessage '*capture fixture failure*'
        Should-Invoke Write-Progress -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $Id -eq 0 -and $Completed }
    }

    It 'rejects diff when the Snapshot belongs to another computer' {
        $path = Join-Path $TestDrive 'diff-wrong-computer.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration)
        $snapshot.computerName = 'OTHER-COMPUTER'
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $snapshot
        { Invoke-NRDiff -Path $path } | Should-Throw -ExceptionMessage '*not*Run capture on this computer*'
    }

    It 'prints changes to other managed resources when diff has no status filter' {
        $path = Join-Path $TestDrive 'diff-other-resources.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallProfiles.Private.Enabled = 'False'
        Write-NRJsonFile -Path $path -InputObject $desired
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration))
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })

        $output = @(Invoke-NRDiff -Path $path) -join [Environment]::NewLine
        $output | Should-MatchString 'Other managed resources:'
        $output | Should-MatchString 'Enabled:'
    }

    It 'does not format other resource changes when a diff status filter is supplied' {
        $path = Join-Path $TestDrive 'diff-status-filter.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallProfiles.Private.Enabled = 'False'
        Write-NRJsonFile -Path $path -InputObject $desired
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration))
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })

        $output = @(Invoke-NRDiff -Path $path -Status 'NewCandidate') -join [Environment]::NewLine
        $output | Should-NotMatchString 'Other managed resources:'
    }

    It 'rejects non-string output from the Firewall classification renderer in diff' {
        $path = Join-Path $TestDrive 'diff-bad-firewall-renderer.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration))
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        Mock Format-NRFirewallRuleClassification -ModuleName PSNetRules { 42 }
        { Invoke-NRDiff -Path $path } | Should-Throw -ExceptionMessage '*diff renderer returned unexpected output type*'
    }

    It 'rejects non-string output from the other-resource diff formatter' {
        $path = Join-Path $TestDrive 'diff-bad-other-renderer.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallProfiles.Private.Enabled = 'False'
        Write-NRJsonFile -Path $path -InputObject $desired
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration))
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        Mock Format-NRDiff -ModuleName PSNetRules { 42 }
        { Invoke-NRDiff -Path $path } | Should-Throw -ExceptionMessage '*diff formatter returned unexpected output type*'
    }

    It 'validates all adopt argument combinations and named-rule eligibility branches' {
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptArguments -Parameters @{ New = $true; Update = $true; Name = @() } } |
            Should-Throw -ExceptionMessage '*cannot be combined*'
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptArguments -Parameters @{ New = $false; Update = $false; Name = @() } } |
            Should-Throw -ExceptionMessage '*Specify -New, -Name, or -Rename*'
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptArguments -Parameters @{ New = $false; Update = $true; Rename = $false; Name = @() } } |
            Should-Throw -ExceptionMessage '*-Update requires -Name*'
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptArguments -Parameters @{ New = $true; Update = $false; Rename = $true; Name = @() } } |
            Should-Throw -ExceptionMessage '*cannot be combined*'
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptArguments -Parameters @{ New = $false; Update = $true; Rename = $true; Name = @('Old-Rule') } } |
            Should-Throw -ExceptionMessage '*-Rename cannot be combined with -Update*'
        Invoke-NRPrivateFunction -Name Assert-NRAdoptArguments -Parameters @{ New = $false; Update = $false; Rename = $true; Name = @() }

        $current = @{ 'Rule-A' = New-NRFixtureFirewallRuleRecord -Name 'Rule-A' }
        $candidate = @([pscustomobject]@{ Name = 'Rule-A'; Status = 'NewCandidate' })
        $base = @{
            Name = 'Rule-A'; Update = $false; CurrentByName = $current; DesiredByName = @{}
            Managed = @{}; Classifications = $candidate
        }
        $emptyNameParameters = $base.Clone()
        $emptyNameParameters.Name = ''
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters $emptyNameParameters } |
            Should-Throw -ExceptionMessage '*Name cannot be empty*'
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters @{
            Name = 'Missing'; Update = $false; CurrentByName = @{}; DesiredByName = @{}; Managed = @{}; Classifications = @()
        } } | Should-Throw -ExceptionMessage '*not present in the latest capture snapshot*'
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters @{
            Name = 'Rule-A'; Update = $true; CurrentByName = $current; DesiredByName = @{}; Managed = @{}; Classifications = $candidate
        } } | Should-Throw -ExceptionMessage '*not currently managed*'
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters @{
            Name = 'Rule-A'; Update = $false; CurrentByName = $current; DesiredByName = @{ 'Rule-A' = $current['Rule-A'] }; Managed = @{}; Classifications = $candidate
        } } | Should-Throw -ExceptionMessage '*already managed*'
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters @{
            Name = 'Rule-A'; Update = $false; CurrentByName = $current; DesiredByName = @{}; Managed = @{};
            Classifications = @([pscustomobject]@{ Name = 'Rule-A'; Status = 'DefaultExcluded' })
        } } | Should-Throw -ExceptionMessage '*not a NewCandidate*'
        Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters $base
        Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters @{
            Name = 'Rule-A'; Update = $false; CurrentByName = $current; DesiredByName = @{}; Managed = @{}
            Classifications = @([pscustomobject]@{ Name = 'Rule-A'; Status = 'Excluded' })
        }
        Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters @{
            Name = 'Rule-A'; Update = $false; CurrentByName = $current; DesiredByName = @{}; Managed = @{ 'Rule-A' = $true }
            Classifications = @([pscustomobject]@{ Name = 'Rule-A'; Status = 'Excluded' })
        }
        Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters @{
            Name = 'Rule-A'; Update = $true; CurrentByName = $current; DesiredByName = @{ 'Rule-A' = $current['Rule-A'] }
            Managed = @{}; Classifications = @()
        }
    }

    It 'prints adoption previews with display names and meaningful filter details' {
        $record = New-NRFixtureFirewallRuleRecord -Name 'Rule-A'
        $record.rule.DisplayName = 'Friendly Rule'
        $record.rule.Group = 'Business Group'
        $record.filters.application.Program = 'C:\Apps\client.exe'
        $record.filters.application.Package = 'Package-A'
        $record.filters.service.Service = 'Service-A'
        $output = @(Invoke-NRPrivateFunction -Name Write-NRAdoptPreview -Parameters @{
            Names = @('Rule-A'); CurrentByName = @{ 'Rule-A' = $record }; Update = $false
        }) -join [Environment]::NewLine
        $output | Should-MatchString 'Rule-A - Friendly Rule'
        $output | Should-MatchString 'Group: Business Group'
        $output | Should-MatchString 'Program: C:\\Apps\\client.exe'
        $output | Should-MatchString 'Package: Package-A'
        $output | Should-MatchString 'Service: Service-A'
    }

    It 'selects all or named unambiguous Rename entries by the old Name' {
        $renames = @(
            [pscustomobject]@{ OldName = 'Old-A'; NewName = 'New-A'; Status = 'Rename' },
            [pscustomobject]@{ OldName = 'Old-B'; NewName = 'New-B'; Status = 'Rename' }
        )
        $all = @(Invoke-NRPrivateFunction -Name Get-NRAdoptRenameSelection -Parameters @{ Names = @(); Classifications = $renames })
        $all.Count | Should-Be 2
        $selected = @(Invoke-NRPrivateFunction -Name Get-NRAdoptRenameSelection -Parameters @{ Names = @('Old-B'); Classifications = $renames })
        $selected.Count | Should-Be 1
        $selected[0].OldName | Should-Be 'Old-B'
        $duplicateSelection = @(Invoke-NRPrivateFunction -Name Get-NRAdoptRenameSelection -Parameters @{ Names = @('Old-B', 'Old-B'); Classifications = $renames })
        $duplicateSelection.Count | Should-Be 1
        { Invoke-NRPrivateFunction -Name Get-NRAdoptRenameSelection -Parameters @{ Names = @('New-A'); Classifications = $renames } } |
            Should-Throw -ExceptionMessage '*No unambiguous Rename was detected*'
    }

    It 'previews Rename adoption using old and new Names' {
        $output = @(Invoke-NRPrivateFunction -Name Write-NRAdoptRenamePreview -Parameters @{
            Renames = @([pscustomobject]@{ OldName = 'Old-Rule'; NewName = 'New-Rule' })
        }) -join [Environment]::NewLine
        $output | Should-MatchString 'Rules to rename: 1'
        $output | Should-MatchString 'Old-Rule -> New-Rule'
    }

    It 'does not create backups when no unambiguous Rename candidates exist' {
        $path = Join-Path $TestDrive 'adopt-no-rename.json'
        $configuration = New-NRFixtureConfiguration
        Write-NRJsonFile -Path $path -InputObject $configuration
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $configuration)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('AllowHttps') })
        Mock New-NRFileBackup -ModuleName PSNetRules { throw 'Backup must not run when no Rename exists.' }

        $output = @(Invoke-NRAdopt -Path $path -Rename -Confirm:$false) -join [Environment]::NewLine
        $output | Should-MatchString 'No unambiguous Rename candidates to adopt\.'
        Should-Invoke New-NRFileBackup -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'accepts selected Rename entries without changing the Snapshot or Windows settings' {
        $path = Join-Path $TestDrive 'adopt-rename-selected.json'
        $oldA = New-NRFixtureFirewallRuleRecord -Name 'Old-A' -DisplayName 'Application A'
        $oldB = New-NRFixtureFirewallRuleRecord -Name 'Old-B' -DisplayName 'Application B'
        $newA = New-NRFixtureFirewallRuleRecord -Name 'New-A' -DisplayName 'Application A'
        $newB = New-NRFixtureFirewallRuleRecord -Name 'New-B' -DisplayName 'Application B'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @($oldA, $oldB)
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @($newA, $newB)
        $snapshotPath = Get-NRSnapshotPath -Path $path
        Write-NRJsonFile -Path $snapshotPath -InputObject (New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration)
        $snapshotBefore = [System.IO.File]::ReadAllText($snapshotPath)
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Old-A', 'Old-B') })
        Mock New-NRFileBackup -ModuleName PSNetRules { @() }

        $output = @(Invoke-NRAdopt -Path $path -Rename -Name 'Old-A' -Confirm:$false) -join [Environment]::NewLine

        $output | Should-MatchString 'Old-A -> New-A'
        $output | Should-MatchString 'Renamed 1 Firewall rules\.'
        $updated = Read-NRConfiguration -Path $path
        @($updated.firewallRules | ForEach-Object name | Sort-Object) | Should-BeCollection @('New-A', 'Old-B')
        $updatedState = Read-NRStateFile -Path $statePath
        @($updatedState.managedFirewallRules | Sort-Object) | Should-BeCollection @('New-A', 'Old-B')
        [System.IO.File]::ReadAllText($snapshotPath) | Should-Be $snapshotBefore
        Should-Invoke New-NRFileBackup -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'previews all unambiguous Rename entries without changing either management file' {
        $path = Join-Path $TestDrive 'adopt-rename-all.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'Old-A' -DisplayName 'Application A'),
            (New-NRFixtureFirewallRuleRecord -Name 'Old-B' -DisplayName 'Application B')
        )
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'New-A' -DisplayName 'Application A'),
            (New-NRFixtureFirewallRuleRecord -Name 'New-B' -DisplayName 'Application B')
        )
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration)
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Old-A', 'Old-B') })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)
        Mock New-NRFileBackup -ModuleName PSNetRules { throw 'Backup must not run during WhatIf.' }

        $preview = @(Invoke-NRAdopt -Path $path -Rename -WhatIf) -join [Environment]::NewLine
        $preview | Should-MatchString 'Rules to rename: 2'
        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
        Should-Invoke New-NRFileBackup -ModuleName PSNetRules -Times 0 -Exactly

    }

    It 'accepts all unambiguous Rename entries and updates Desired State plus managed inventory' {
        $path = Join-Path $TestDrive 'adopt-rename-all.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'Old-A' -DisplayName 'Application A'),
            (New-NRFixtureFirewallRuleRecord -Name 'Old-B' -DisplayName 'Application B')
        )
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'New-A' -DisplayName 'Application A'),
            (New-NRFixtureFirewallRuleRecord -Name 'New-B' -DisplayName 'Application B')
        )
        $snapshotPath = Get-NRSnapshotPath -Path $path
        Write-NRJsonFile -Path $snapshotPath -InputObject (New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration)
        $snapshotBefore = [System.IO.File]::ReadAllText($snapshotPath)
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Old-A', 'Old-B') })

        $output = @(Invoke-NRAdopt -Path $path -Rename -Confirm:$false) -join [Environment]::NewLine

        $output | Should-MatchString 'Renamed 2 Firewall rules\.'
        $updated = Read-NRConfiguration -Path $path
        @($updated.firewallRules | ForEach-Object name | Sort-Object) | Should-BeCollection @('New-A', 'New-B')
        $updatedState = Read-NRStateFile -Path $statePath
        @($updatedState.managedFirewallRules | Sort-Object) | Should-BeCollection @('New-A', 'New-B')
        [System.IO.File]::ReadAllText($snapshotPath) | Should-Be $snapshotBefore
        $classifications = @(Get-NRFirewallRuleClassification -Snapshot (Read-NRSnapshot -Path $snapshotPath) -Desired $updated -State $updatedState)
        @($classifications | Where-Object Status -eq 'InSync').Count | Should-Be 2
        @($classifications | Where-Object Status -eq 'Rename').Count | Should-Be 0
    }

    It 'adopts an explicitly excluded rule by Name and clears its exclusion' {
        $path = Join-Path $TestDrive 'adopt-excluded.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        $desired.excludedFirewallRules = @('Rule-A')
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration)
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })

        Invoke-NRAdopt -Path $path -Name 'Rule-A' -Confirm:$false | Out-Null

        $updated = Read-NRConfiguration -Path $path
        @($updated.excludedFirewallRules).Count | Should-Be 0
        @($updated.firewallRules | Where-Object name -eq 'Rule-A').Count | Should-Be 1
        (@((Read-NRStateFile -Path $statePath).managedFirewallRules) -contains 'Rule-A') | Should-Be $true
    }

    It 'does not select excluded rules with adopt -New or create backups' {
        $path = Join-Path $TestDrive 'adopt-none.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        $desired.excludedFirewallRules = @('Excluded-Rule')
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Excluded-Rule'))
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $snapshot
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        Mock New-NRFileBackup -ModuleName PSNetRules { throw 'Backup must not run when no rules are selected.' }

        $output = @(Invoke-NRAdopt -Path $path -New -Confirm:$false) -join [Environment]::NewLine
        $output | Should-MatchString 'No rules to adopt\.'
        (@((Read-NRConfiguration -Path $path).excludedFirewallRules) -contains 'Excluded-Rule') | Should-Be $true
        Should-Invoke New-NRFileBackup -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'writes and reports pre-adoption backups when rules are adopted' {
        $path = Join-Path $TestDrive 'adopt-with-backups.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration))
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })

        $output = @(Invoke-NRAdopt -Path $path -New -Confirm:$false) -join [Environment]::NewLine
        $backupDirectory = Join-Path $TestDrive 'backups'
        $backupBaseName = [System.IO.Path]::GetFileNameWithoutExtension($path)
        $backupFiles = @(Get-ChildItem -LiteralPath $backupDirectory -Filter ($backupBaseName + '*.pre-adopt.*') -File)
        $backupFiles.Count | Should-Be 2
        $output | Should-MatchString 'Backup: .*pre-adopt'
        ($backupFiles.Name -join ' ') | Should-MatchString 'adopt-with-backups'
        (Read-NRConfiguration -Path $path).firewallRules.Count | Should-Be 1
    }

    It 'rejects adoption from a Snapshot captured on another computer before making backups' {
        $path = Join-Path $TestDrive 'adopt-wrong-computer.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $desired
        $snapshot.computerName = 'OTHER-COMPUTER'
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $snapshot
        Mock New-NRFileBackup -ModuleName PSNetRules { throw 'Backup must not run for a foreign Snapshot.' }

        { Invoke-NRAdopt -Path $path -New -Confirm:$false } |
            Should-Throw -ExceptionMessage '*Snapshot belongs to computer*'
        Should-Invoke New-NRFileBackup -ModuleName PSNetRules -Times 0 -Exactly
    }

    It 'unmanages multiple Firewall rules from Desired State and the managed inventory while preserving other state' {
        $path = Join-Path $TestDrive 'unmanage-both.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'Rule-A'),
            (New-NRFixtureFirewallRuleRecord -Name 'Rule-B'),
            (New-NRFixtureFirewallRuleRecord -Name 'Rule-C')
        )
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        $state = [pscustomobject]@{
            nrptRules = @{ 'corp-dns' = '{22222222-2222-2222-2222-222222222222}' }
            managedFirewallRules = @('Rule-A', 'Rule-B', 'Rule-C')
        }
        Write-NRStateFile -Path $statePath -State $state
        $snapshotPath = Get-NRSnapshotPath -Path $path
        [System.IO.File]::WriteAllText($snapshotPath, 'snapshot-must-remain-unchanged')
        $snapshotBefore = [System.IO.File]::ReadAllText($snapshotPath)
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)

        $output = @(Invoke-NRUnmanage -Path $path -Name @('Rule-A', 'rule-b', 'Rule-A') -Confirm:$false) -join [Environment]::NewLine

        $updatedDesired = Read-NRConfiguration -Path $path
        @($updatedDesired.firewallRules | ForEach-Object { $_.name }) | Should-BeCollection @('Rule-C')
        @($updatedDesired.excludedFirewallRules) | Should-BeCollection @('Rule-A', 'Rule-B')
        $updatedState = Read-NRStateFile -Path $statePath
        @($updatedState.managedFirewallRules) | Should-BeCollection @('Rule-C')
        $updatedState.nrptRules['corp-dns'] | Should-Be '{22222222-2222-2222-2222-222222222222}'
        [System.IO.File]::ReadAllText($snapshotPath) | Should-Be $snapshotBefore
        $output | Should-MatchString 'Rules to unmanage: 2'
        $output | Should-MatchString 'Unmanaged 2 Firewall rules'

        $backupFiles = @(Get-NRTestUnmanageBackups -ConfigurationPath $path)
        $backupFiles.Count | Should-Be 2
        $configurationBackup = Get-Content -LiteralPath (@($backupFiles | Where-Object Name -like 'unmanage-both.pre-unmanage.*.json')[0].FullName) -Raw
        $stateBackup = Get-Content -LiteralPath (@($backupFiles | Where-Object Name -like 'unmanage-both.state.pre-unmanage.*.json')[0].FullName) -Raw
        $configurationBackup | Should-Be $configurationBefore
        $stateBackup | Should-Be $stateBefore
    }

    It 'unmanages a NewCandidate by persisting an exclusion without changing the snapshot or Windows boundary' {
        $path = Join-Path $TestDrive 'unmanage-new-candidate.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'New-Candidate'))
        $snapshotPath = Get-NRSnapshotPath -Path $path
        Write-NRJsonFile -Path $snapshotPath -InputObject (New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration)
        $snapshotBefore = [System.IO.File]::ReadAllText($snapshotPath)
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })

        $output = @(Invoke-NRUnmanage -Path $path -Name 'New-Candidate' -Confirm:$false) -join [Environment]::NewLine

        $updated = Read-NRConfiguration -Path $path
        @($updated.excludedFirewallRules) | Should-BeCollection @('New-Candidate')
        @($updated.firewallRules).Count | Should-Be 0
        @((Read-NRStateFile -Path $statePath).managedFirewallRules).Count | Should-Be 0
        [System.IO.File]::ReadAllText($snapshotPath) | Should-Be $snapshotBefore
        $output | Should-MatchString 'Windows Firewall settings were not changed'
        $classifications = @(Get-NRFirewallRuleClassification -Snapshot (Read-NRSnapshot -Path $snapshotPath) -Desired $updated -State (Read-NRStateFile -Path $statePath))
        @($classifications | Where-Object { $_.Name -eq 'New-Candidate' -and $_.Status -eq 'Excluded' }).Count | Should-Be 1
    }

    It 'rejects a NewCandidate from a Snapshot belonging to another computer without changing files' {
        $path = Join-Path $TestDrive 'unmanage-foreign-snapshot.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $snapshotConfiguration = New-NRFixtureConfiguration
        $snapshotConfiguration.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Foreign-Candidate'))
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration $snapshotConfiguration
        $snapshot.computerName = ('OTHER-' + $env:COMPUTERNAME)
        $snapshotPath = Get-NRSnapshotPath -Path $path
        Write-NRJsonFile -Path $snapshotPath -InputObject $snapshot
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)

        { Invoke-NRUnmanage -Path $path -Name 'Foreign-Candidate' -Confirm:$false } |
            Should-Throw -ExceptionMessage '*Snapshot belongs to computer*'

        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
    }

    It 'treats an already excluded rule as an idempotent no-op' {
        $path = Join-Path $TestDrive 'unmanage-already-excluded.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        $desired.excludedFirewallRules = @('Excluded-Rule')
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)

        $output = @(Invoke-NRUnmanage -Path $path -Name 'Excluded-Rule' -Confirm:$false) -join [Environment]::NewLine

        $output | Should-MatchString 'No rules to unmanage\.'
        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
    }

    It 'clears a managed-name tombstone even when the rule is absent from Desired State' {
        $path = Join-Path $TestDrive 'unmanage-tombstone.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{
            nrptRules = @{ 'corp-dns' = '{33333333-3333-3333-3333-333333333333}' }
            managedFirewallRules = @('Deleted-Rule', 'Other-Rule')
        })

        $output = @(Invoke-NRUnmanage -Path $path -Name 'Deleted-Rule' -Confirm:$false) -join [Environment]::NewLine

        @(Read-NRConfiguration -Path $path).firewallRules.Count | Should-Be 0
        $state = Read-NRStateFile -Path $statePath
        @($state.managedFirewallRules) | Should-BeCollection @('Other-Rule')
        $state.nrptRules['corp-dns'] | Should-Be '{33333333-3333-3333-3333-333333333333}'
        $output | Should-MatchString 'Unmanaged 1 Firewall rules'
    }

    It 'unmanages a Desired State-only rule and initializes an absent state sidecar' {
        $path = Join-Path $TestDrive 'unmanage-no-state.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Desired-Only'))
        $desired.PSObject.Properties.Remove('excludedFirewallRules')
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        (Test-Path -LiteralPath $statePath) | Should-Be $false

        Invoke-NRUnmanage -Path $path -Name 'Desired-Only' -Confirm:$false | Out-Null

        $updated = Read-NRConfiguration -Path $path
        @($updated.excludedFirewallRules) | Should-BeCollection @('Desired-Only')
        @($updated.firewallRules).Count | Should-Be 0
        (Test-Path -LiteralPath $statePath -PathType Leaf) | Should-Be $true
        @((Read-NRStateFile -Path $statePath).managedFirewallRules).Count | Should-Be 0
        $backups = @(Get-NRTestUnmanageBackups -ConfigurationPath $path)
        $backups.Count | Should-Be 1
        $backups[0].Name | Should-MatchString 'unmanage-no-state\.pre-unmanage\.'
    }

    It 'rejects a State path that exists as a directory' {
        $path = Join-Path $TestDrive 'unmanage-state-directory.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        $statePath = Get-NRStatePath -Path $path
        New-Item -ItemType Directory -Path $statePath -Force | Out-Null
        $configurationBefore = [System.IO.File]::ReadAllText($path)

        { Invoke-NRUnmanage -Path $path -Name 'AllowHttps' -Confirm:$false } |
            Should-Throw -ExceptionMessage '*State path exists but is not a file*'

        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        @(Get-ChildItem -LiteralPath $statePath -Force).Count | Should-Be 0
    }

    It 'validates every requested name before creating backups or changing either file' {
        $path = Join-Path $TestDrive 'unmanage-atomic-validation.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A') })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)

        { Invoke-NRUnmanage -Path $path -Name @('Rule-A', 'Unknown-Rule') -Confirm:$false } |
            Should-Throw -ExceptionMessage '*not found in Desired State, managed inventory, or the latest Snapshot*'

        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
        @(Get-NRTestUnmanageBackups -ConfigurationPath $path).Count | Should-Be 0
    }

    It 'does not change management files or create backups during WhatIf' {
        $path = Join-Path $TestDrive 'unmanage-whatif.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A') })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)

        $output = @(Invoke-NRUnmanage -Path $path -Name 'Rule-A' -WhatIf) -join [Environment]::NewLine

        $output | Should-MatchString 'Rules to unmanage: 1'
        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
        @(Get-NRTestUnmanageBackups -ConfigurationPath $path).Count | Should-Be 0
        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.unmanage.*.tmp' -File).Count | Should-Be 0
    }

    It 'restores both original management files when replacing the state file fails' {
        $path = Join-Path $TestDrive 'unmanage-rollback.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A') })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)
        Mock Move-NRManagedFile -ModuleName PSNetRules {
            # Inject a failure only for the State-file replacement; allow the
            # configuration-file replacement and rollback path to run normally.
            if ([string]$DestinationPath -like '*unmanage-rollback.state.json') {
                throw 'Injected state replacement failure.'
            }
            Microsoft.PowerShell.Management\Move-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop | Out-Null
        }

        { Invoke-NRUnmanage -Path $path -Name 'Rule-A' -Confirm:$false } |
            Should-Throw -ExceptionMessage '*Injected state replacement failure*'

        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
        Should-Invoke Move-NRManagedFile -ModuleName PSNetRules -Times 1 -Exactly -ParameterFilter { $DestinationPath -like '*unmanage-rollback.state.json' }
    }

    It 'does not commit when the configuration backup cannot be created' {
        $path = Join-Path $TestDrive 'unmanage-no-config-backup.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A') })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)
        Mock New-NRFileBackup -ModuleName PSNetRules { @() }

        { Invoke-NRUnmanage -Path $path -Name 'Rule-A' -Confirm:$false } |
            Should-Throw -ExceptionMessage '*Unable to create the configuration backup*'

        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
        @(Get-NRTestUnmanageBackups -ConfigurationPath $path).Count | Should-Be 0
    }

    It 'does not commit when the existing State file has no matching backup' {
        $path = Join-Path $TestDrive 'unmanage-no-state-backup.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A') })
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        $stateBefore = [System.IO.File]::ReadAllText($statePath)
        Mock New-NRFileBackup -ModuleName PSNetRules { @('configuration-backup.json') }

        { Invoke-NRUnmanage -Path $path -Name 'Rule-A' -Confirm:$false } |
            Should-Throw -ExceptionMessage '*Unable to create the state backup*'

        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        [System.IO.File]::ReadAllText($statePath) | Should-Be $stateBefore
    }

    It 'reports a failed rollback and retains the pre-unmanage backups' {
        $path = Join-Path $TestDrive 'unmanage-rollback-failure.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A') })
        Mock Move-NRManagedFile -ModuleName PSNetRules {
            if ([string]$DestinationPath -like '*unmanage-rollback-failure.state.json') {
                throw 'Injected state replacement failure.'
            }
            Microsoft.PowerShell.Management\Move-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop | Out-Null
        }
        Mock Copy-NRManagedFile -ModuleName PSNetRules {
            # Let backup creation succeed. Inject the failure only when the
            # rollback target is the original configuration file.
            if ([string]$DestinationPath -like '*unmanage-rollback-failure.json') {
                throw 'Injected configuration rollback failure.'
            }
            Microsoft.PowerShell.Management\Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop | Out-Null
        }

        { Invoke-NRUnmanage -Path $path -Name 'Rule-A' -Confirm:$false } |
            Should-Throw -ExceptionMessage '*Rollback also failed*configuration rollback*'

        $backupFiles = @(Get-NRTestUnmanageBackups -ConfigurationPath $path)
        $backupFiles.Count | Should-Be 2
        ($backupFiles.Name -join ' ') | Should-MatchString 'pre-unmanage'
    }

    It 'removes a newly created state file during rollback when it did not exist before' {
        $path = Join-Path $TestDrive 'unmanage-rollback-no-state.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Rule-A'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $statePath = Get-NRStatePath -Path $path
        $configurationBefore = [System.IO.File]::ReadAllText($path)
        Mock Move-NRManagedFile -ModuleName PSNetRules {
            if ([string]$DestinationPath -like '*unmanage-rollback-no-state.state.json') {
                [System.IO.File]::WriteAllText([string]$DestinationPath, 'partial state file')
                throw 'Injected state replacement failure.'
            }
            Microsoft.PowerShell.Management\Move-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop | Out-Null
        }

        { Invoke-NRUnmanage -Path $path -Name 'Rule-A' -Confirm:$false } |
            Should-Throw -ExceptionMessage '*Injected state replacement failure*'

        [System.IO.File]::ReadAllText($path) | Should-Be $configurationBefore
        (Test-Path -LiteralPath $statePath) | Should-Be $false
    }

    It 'classifies an unmanaged Firewall rule as unmanaged and does not generate its deletion' {
        $path = Join-Path $TestDrive 'unmanage-diff-generate.json'
        $configuration = New-NRFixtureConfiguration
        $configuration.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'Rule-A'),
            (New-NRFixtureFirewallRuleRecord -Name 'Rule-B')
        )
        Write-NRJsonFile -Path $path -InputObject $configuration
        $snapshotPath = Get-NRSnapshotPath -Path $path
        Write-NRJsonFile -Path $snapshotPath -InputObject (New-NRFixtureCaptureSnapshot -Configuration $configuration)
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A', 'Rule-B') })

        Invoke-NRUnmanage -Path $path -Name 'Rule-A' -Confirm:$false | Out-Null
        $desiredAfter = Read-NRConfiguration -Path $path
        Read-NRStateFile -Path $statePath
        $snapshotAfter = Read-NRSnapshot -Path $snapshotPath

        # Capture must preserve the exclusion while the Rule is still present
        # in the latest Snapshot; presence must not restore managed status.
        Invoke-NRPrivateFunction -Name Update-NRCaptureManagedFirewallState -Parameters @{
            StatePath = $statePath; Snapshot = $snapshotAfter; Desired = $desiredAfter
        }
        $stateAfterCapture = Read-NRStateFile -Path $statePath
        @($stateAfterCapture.managedFirewallRules) | Should-BeCollection @('Rule-B')

        $classifications = @(Get-NRFirewallRuleClassification -Snapshot $snapshotAfter -Desired $desiredAfter -State $stateAfterCapture)
        $unmanaged = @($classifications | Where-Object Name -eq 'Rule-A')
        $unmanaged.Count | Should-Be 1
        $unmanaged[0].Management | Should-Be 'Excluded'
        $unmanaged[0].Status | Should-Be 'Excluded'
        (@($desiredAfter.excludedFirewallRules) -contains 'Rule-A') | Should-Be $true

        # The explicit exclusion takes precedence over a stale managed-name
        # entry in the State sidecar when the generated plan is built.
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Rule-A', 'Rule-B') })
        $generatedPath = Join-Path $TestDrive 'unmanage-diff-generate.ps1'
        Invoke-NRGenerate -Path $path -OutputPath $generatedPath -Confirm:$false | Out-Null
        $generated = Get-Content -LiteralPath $generatedPath -Raw
        $generated | Should-NotMatchString "Remove-NetFirewallRule -Name 'Rule-A'"
    }

    It 'validates unmanage selection inputs and deduplicates names case-insensitively' {
        { Invoke-NRPrivateFunction -Name Get-NRUnmanageSelection -Parameters @{ Names = @(); DesiredNames = @('Rule-A'); ManagedNames = @() } } |
            Should-Throw -ExceptionMessage '*Specify one or more -Name*'
        { Invoke-NRPrivateFunction -Name Get-NRUnmanageSelection -Parameters @{ Names = @(''); DesiredNames = @('Rule-A'); ManagedNames = @() } } |
            Should-Throw -ExceptionMessage '*Name cannot be empty*'
        { Invoke-NRPrivateFunction -Name Get-NRUnmanageSelection -Parameters @{ Names = @('Missing'); DesiredNames = @('Rule-A'); ManagedNames = @() } } |
            Should-Throw -ExceptionMessage '*not found in Desired State, managed inventory, or the latest Snapshot*'

        $selected = @(Invoke-NRPrivateFunction -Name Get-NRUnmanageSelection -Parameters @{
            Names = @('rule-a', 'RULE-A', 'Rule-B', 'Candidate-A'); DesiredNames = @('Rule-A'); ManagedNames = @('Rule-B')
            CurrentNames = @('Candidate-A')
        })
        $selected | Should-BeCollection @('Rule-A', 'Rule-B', 'Candidate-A')

        $alreadyExcluded = @(Invoke-NRPrivateFunction -Name Get-NRUnmanageSelection -Parameters @{
            Names = @('Excluded-A'); DesiredNames = @(); ManagedNames = @(); CurrentNames = @(); ExcludedNames = @('Excluded-A')
        })
        $alreadyExcluded.Count | Should-Be 0

        $staleManagedExclusion = @(Invoke-NRPrivateFunction -Name Get-NRUnmanageSelection -Parameters @{
            Names = @('Excluded-A'); DesiredNames = @(); ManagedNames = @('Excluded-A'); CurrentNames = @(); ExcludedNames = @('Excluded-A')
        })
        $staleManagedExclusion | Should-BeCollection @('Excluded-A')
    }

    It 'restores the desired file and reports rollback errors when the state backup is unavailable' {
        $configurationPath = Join-Path $TestDrive 'rollback-helper.json'
        $configurationBackup = Join-Path $TestDrive 'rollback-helper.backup.json'
        $statePath = Join-Path $TestDrive 'rollback-helper.state.json'
        [System.IO.File]::WriteAllText($configurationBackup, 'original configuration')
        [System.IO.File]::WriteAllText($configurationPath, 'changed configuration')
        [System.IO.File]::WriteAllText($statePath, 'changed state')

        $errors = @(Invoke-NRPrivateFunction -Name Restore-NRUnmanageFiles -Parameters @{
            ConfigurationPath = $configurationPath; ConfigurationBackup = $configurationBackup
            StatePath = $statePath; StateBackup = (Join-Path $TestDrive 'missing-state-backup.json'); StateExisted = $true
        })

        [System.IO.File]::ReadAllText($configurationPath) | Should-Be 'original configuration'
        $errors.Count | Should-Be 1
        $errors[0] | Should-MatchString 'state rollback:'
    }

    It 'serializes nested PowerShell literals and escapes strings without losing types' {
        (ConvertTo-NRPowerShellLiteral $null) | Should-Be '$null'
        (ConvertTo-NRPowerShellLiteral $true) | Should-Be '$true'
        (ConvertTo-NRPowerShellLiteral $false) | Should-Be '$false'
        (ConvertTo-NRPowerShellLiteral ([System.DayOfWeek]::Monday)) | Should-Be "'Monday'"
        (ConvertTo-NRPowerShellLiteral 12) | Should-Be '12'
        (ConvertTo-NRPowerShellLiteral "it's") | Should-Be "'it''s'"
        (ConvertTo-NRPowerShellLiteral @('a', 'b')) | Should-Be "@('a', 'b')"
        (ConvertTo-NRPowerShellLiteral @{ a = 1 }) | Should-Be "@{'a' = 1}"
        (ConvertTo-NRPowerShellLiteral ([ordered]@{ z = 2; a = [ordered]@{ inner = "it's" } })) |
            Should-Be "@{'a' = @{'inner' = 'it''s'}; 'z' = 2}"
        (ConvertTo-NRPowerShellLiteral ([pscustomobject]@{ Name = 'Rule-A' })) | Should-Be "'@{Name=Rule-A}'"
    }

    It 'detects recreated dynamic keyword IDs for keyword, auto-resolve, and removal changes' {
        $current = @{
            unchanged = [pscustomobject]@{ Keyword = 'K1'; AutoResolve = $false }
            keyword = [pscustomobject]@{ Keyword = 'K1'; AutoResolve = $false }
            resolve = [pscustomobject]@{ Keyword = 'K2'; AutoResolve = $false }
            removed = [pscustomobject]@{ Keyword = 'K3'; AutoResolve = $true }
        }
        $desired = @{
            unchanged = [pscustomobject]@{ Keyword = 'K1'; AutoResolve = $false }
            keyword = [pscustomobject]@{ Keyword = 'K9'; AutoResolve = $false }
            resolve = [pscustomobject]@{ Keyword = 'K2'; AutoResolve = $true }
            added = [pscustomobject]@{ Keyword = 'K4'; AutoResolve = $true }
        }
        $ids = Invoke-NRPrivateFunction -Name Get-NRRecreatedDynamicKeywordIds -Parameters @{
            CurrentDynamic = $current; DesiredDynamic = $desired
        }
        @($ids | Sort-Object) | Should-BeCollection @('keyword', 'removed', 'resolve')
    }

    It 'removes managed dependent Firewall rules before recreating a dynamic keyword address' {
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $record = [pscustomobject]@{
            name = 'ManagedRule'
            rule = [pscustomobject]@{ RemoteDynamicKeywordAddresses = @('keyword-id') }
        }
        $force = @{}
        $preRemoved = @{}
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDependentRuleRemovalCommands -Parameters @{
            Lines = $lines; FirewallRules = @($record); RecreatedIds = @('keyword-id')
            ManagedNames = @{ ManagedRule = $true }; DesiredRules = @{ ManagedRule = $true }
            ForceRecreate = $force; PreRemoved = $preRemoved
        }
        $preRemoved.ContainsKey('ManagedRule') | Should-Be $true
        $force.ContainsKey('ManagedRule') | Should-Be $true
        ($lines -join "`n") | Should-MatchString 'Remove-NetFirewallRule.*ManagedRule'
    }

    It 'rejects dynamic keyword recreation when an unmanaged Firewall rule depends on it' {
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $record = [pscustomobject]@{ name = 'UnmanagedRule'; rule = [pscustomobject]@{ RemoteDynamicKeywordAddresses = @('keyword-id') } }
        { Invoke-NRPrivateFunction -Name Add-NRGeneratedDependentRuleRemovalCommands -Parameters @{
            Lines = $lines; FirewallRules = @($record); RecreatedIds = @('keyword-id')
            ManagedNames = @{}; DesiredRules = @{}; ForceRecreate = @{}; PreRemoved = @{}
        } } | Should-Throw -ExceptionMessage '*unmanaged Firewall rule*'
    }

    It 'skips unrelated dependent Firewall rules and tracks dependencies that are not in Desired State' {
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $force = @{}
        $preRemoved = @{}
        $records = @(
            [pscustomobject]@{ name = 'NoMatch'; rule = [pscustomobject]@{ RemoteDynamicKeywordAddresses = @('another-id') } },
            [pscustomobject]@{ name = 'RemovedFromDesired'; rule = [pscustomobject]@{ RemoteDynamicKeywordAddresses = @('keyword-id') } }
        )
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDependentRuleRemovalCommands -Parameters @{
            Lines = $lines; FirewallRules = $records; RecreatedIds = @('keyword-id')
            ManagedNames = @{ RemovedFromDesired = $true }; DesiredRules = @{}
            ForceRecreate = $force; PreRemoved = $preRemoved
        }
        $lines.Count | Should-Be 1
        $preRemoved.ContainsKey('RemovedFromDesired') | Should-Be $true
        $force.Count | Should-Be 0
    }

    It 'generates create, recreate, update, and no-op dynamic keyword commands' {
        $id = '{eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee}'
        $desired = [pscustomobject]@{ id = $id; Keyword = 'NewKeyword'; Addresses = '192.0.2.20'; AutoResolve = $false }

        $newLines = New-Object 'System.Collections.Generic.List[string]'
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDynamicAddressCommand -Parameters @{
            Lines = $newLines; Id = $id; Record = $desired; CurrentRecord = $null
        }
        ($newLines -join "`n") | Should-MatchString 'New-NetFirewallDynamicKeywordAddress'

        $recreateLines = New-Object 'System.Collections.Generic.List[string]'
        $old = [pscustomobject]@{ id = $id; Keyword = 'OldKeyword'; Addresses = '192.0.2.10'; AutoResolve = $false }
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDynamicAddressCommand -Parameters @{
            Lines = $recreateLines; Id = $id; Record = $desired; CurrentRecord = $old
        }
        ($recreateLines -join "`n") | Should-MatchString 'Remove-NetFirewallDynamicKeywordAddress'
        ($recreateLines -join "`n") | Should-MatchString 'New-NetFirewallDynamicKeywordAddress'

        $updateLines = New-Object 'System.Collections.Generic.List[string]'
        $sameKeyword = [pscustomobject]@{ id = $id; Keyword = 'NewKeyword'; Addresses = '192.0.2.10'; AutoResolve = $false }
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDynamicAddressCommand -Parameters @{
            Lines = $updateLines; Id = $id; Record = $desired; CurrentRecord = $sameKeyword
        }
        ($updateLines -join "`n") | Should-MatchString 'Update-NetFirewallDynamicKeywordAddress'

        $autoLines = New-Object 'System.Collections.Generic.List[string]'
        $autoCurrent = [pscustomobject]@{ id = $id; Keyword = 'NewKeyword'; Addresses = ''; AutoResolve = $true }
        $autoDesired = [pscustomobject]@{ id = $id; Keyword = 'NewKeyword'; Addresses = ''; AutoResolve = $true }
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDynamicAddressCommand -Parameters @{
            Lines = $autoLines; Id = $id; Record = $autoDesired; CurrentRecord = $autoCurrent
        }
        $autoLines.Count | Should-Be 0

        $sameLines = New-Object 'System.Collections.Generic.List[string]'
        $sameAddress = [pscustomobject]@{ id = $id; Keyword = 'NewKeyword'; Addresses = '192.0.2.20'; AutoResolve = $false }
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDynamicAddressCommand -Parameters @{
            Lines = $sameLines; Id = $id; Record = $desired; CurrentRecord = $sameAddress
        }
        $sameLines.Count | Should-Be 0
    }

    It 'generates removal commands for dynamic keyword addresses absent from Desired State' {
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $current = @{ stale = [pscustomobject]@{ id = 'stale'; Keyword = 'K'; Addresses = '192.0.2.1'; AutoResolve = $false } }
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDynamicAddressCommands -Parameters @{
            Lines = $lines; CurrentDynamic = $current; DesiredDynamic = @{}
        }
        ($lines -join "`n") | Should-MatchString 'Remove-NetFirewallDynamicKeywordAddress.*stale'

        $lines.Clear()
        $desired = @{ added = [pscustomobject]@{ id = 'added'; Keyword = 'K2'; Addresses = '192.0.2.2'; AutoResolve = $false } }
        Invoke-NRPrivateFunction -Name Add-NRGeneratedDynamicAddressCommands -Parameters @{
            Lines = $lines; CurrentDynamic = @{}; DesiredDynamic = $desired
        }
        ($lines -join "`n") | Should-MatchString 'New-NetFirewallDynamicKeywordAddress.*K2'
    }

    It 'generates Firewall rule commands for create, update, recreate, pre-removed, and stale cases' {
        $desired = New-NRFixtureFirewallRuleRecord -Name 'Rule-A'
        $lines = New-Object 'System.Collections.Generic.List[string]'
        Invoke-NRPrivateFunction -Name Add-NRGeneratedFirewallRuleCommand -Parameters @{
            Lines = $lines; Name = 'Rule-A'; DesiredRecord = $desired; CurrentRecord = $null
            ForceRecreate = $false; PreRemoved = $false
        }
        ($lines -join "`n") | Should-MatchString 'New-NetFirewallRule'

        $lines.Clear()
        $mutable = New-NRFixtureFirewallRuleRecord -Name 'Rule-A'
        $mutable.rule.Description = 'Updated'
        Invoke-NRPrivateFunction -Name Add-NRGeneratedFirewallRuleCommand -Parameters @{
            Lines = $lines; Name = 'Rule-A'; DesiredRecord = $mutable; CurrentRecord = $desired
            ForceRecreate = $false; PreRemoved = $false
        }
        ($lines -join "`n") | Should-MatchString 'Set-NetFirewallRule'
        ($lines -join "`n") | Should-MatchString 'NewDisplayName'
        ($lines -join "`n") | Should-NotMatchString ' -Group '

        $lines.Clear()
        $recreate = New-NRFixtureFirewallRuleRecord -Name 'Rule-A'
        $recreate.rule.Group = 'NewGroup'
        Invoke-NRPrivateFunction -Name Add-NRGeneratedFirewallRuleCommand -Parameters @{
            Lines = $lines; Name = 'Rule-A'; DesiredRecord = $recreate; CurrentRecord = $desired
            ForceRecreate = $false; PreRemoved = $false
        }
        ($lines -join "`n") | Should-MatchString 'Remove-NetFirewallRule'
        ($lines -join "`n") | Should-MatchString 'New-NetFirewallRule'

        $lines.Clear()
        Invoke-NRPrivateFunction -Name Add-NRGeneratedFirewallRuleCommand -Parameters @{
            Lines = $lines; Name = 'Rule-A'; DesiredRecord = $recreate; CurrentRecord = $desired
            ForceRecreate = $true; PreRemoved = $true
        }
        ($lines -join "`n") | Should-NotMatchString 'Remove-NetFirewallRule'
        ($lines -join "`n") | Should-MatchString 'New-NetFirewallRule'

        $lines.Clear()
        Invoke-NRPrivateFunction -Name Add-NRGeneratedFirewallRuleCommand -Parameters @{
            Lines = $lines; Name = 'Rule-A'; DesiredRecord = $desired; CurrentRecord = $desired
            ForceRecreate = $false; PreRemoved = $false
        }
        $lines.Count | Should-Be 0
    }

    It 'generates stale Firewall deletion and changed Firewall Profile commands' {
        $lines = New-Object 'System.Collections.Generic.List[string]'
        Invoke-NRPrivateFunction -Name Add-NRGeneratedFirewallRuleCommands -Parameters @{
            Lines = $lines; CurrentRules = @{ StaleRule = (New-NRFixtureFirewallRuleRecord -Name 'StaleRule') }
            DesiredRules = @{}; ManagedNames = @('StaleRule'); ForceRecreate = @{}; PreRemoved = @{}
        }
        ($lines -join "`n") | Should-MatchString 'Remove-NetFirewallRule.*StaleRule'

        $lines.Clear()
        $desired = New-NRFixtureConfiguration
        $snapshot = New-NRFixtureConfiguration
        $desired.firewallProfiles.Private.Enabled = 'False'
        Invoke-NRPrivateFunction -Name Add-NRGeneratedFirewallProfileCommands -Parameters @{
            Lines = $lines; Desired = $desired; SnapshotConfiguration = $snapshot
        }
        ($lines -join "`n") | Should-MatchString 'Set-NetFirewallProfile'
        ($lines -join "`n") | Should-MatchString 'Private'
    }

    It 'plans dynamic keyword dependencies and desired-only Firewall rules together' {
        $id = 'dynamic-id'
        $currentRule = New-NRFixtureFirewallRuleRecord -Name 'DependentRule'
        $currentRule.rule.RemoteDynamicKeywordAddresses = @($id)
        $snapshot = [pscustomobject]@{
            firewallDynamicKeywordAddresses = @([pscustomobject]@{ id = $id; Keyword = 'Old'; Addresses = '192.0.2.1'; AutoResolve = $false })
            firewallRules = @($currentRule)
        }
        $desiredRule = New-NRFixtureFirewallRuleRecord -Name 'DependentRule'
        $desiredRule.rule.RemoteDynamicKeywordAddresses = @($id)
        $newRule = New-NRFixtureFirewallRuleRecord -Name 'NewRule'
        $desired = [pscustomobject]@{
            firewallDynamicKeywordAddresses = @([pscustomobject]@{ id = $id; Keyword = 'New'; Addresses = '192.0.2.2'; AutoResolve = $false })
            firewallRules = @($desiredRule, $newRule)
        }
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $desiredMap = @{ DependentRule = $desiredRule; NewRule = $newRule }
        $plan = Invoke-NRPrivateFunction -Name Add-NRGeneratedDynamicKeywordCommands -Parameters @{
            Lines = $lines; SnapshotConfiguration = $snapshot; Desired = $desired
            ManagedNames = @{ DependentRule = $true }; DesiredRules = $desiredMap
        }
        $plan.ForceRecreate.ContainsKey('DependentRule') | Should-Be $true
        $plan.PreRemoved.ContainsKey('DependentRule') | Should-Be $true
        ($lines -join "`n") | Should-MatchString 'Remove-NetFirewallRule.*DependentRule'
        ($lines -join "`n") | Should-MatchString 'Remove-NetFirewallDynamicKeywordAddress'
        ($lines -join "`n") | Should-MatchString 'New-NetFirewallDynamicKeywordAddress'

        $ruleLines = New-Object 'System.Collections.Generic.List[string]'
        $staleRule = New-NRFixtureFirewallRuleRecord -Name 'OldStale'
        $preRemovedRule = New-NRFixtureFirewallRuleRecord -Name 'PreRemoved'
        Invoke-NRPrivateFunction -Name Add-NRGeneratedFirewallRuleCommands -Parameters @{
            Lines = $ruleLines; CurrentRules = @{ DependentRule = $currentRule; OldStale = $staleRule; PreRemoved = $preRemovedRule }
            DesiredRules = $desiredMap
            ManagedNames = @('DependentRule', 'OldStale', 'PreRemoved')
            ForceRecreate = $plan.ForceRecreate; PreRemoved = ($plan.PreRemoved + @{ PreRemoved = $true })
        }
        ($ruleLines -join "`n") | Should-MatchString 'New-NetFirewallRule.*NewRule'
        ($ruleLines -join "`n") | Should-MatchString 'Remove-NetFirewallRule.*OldStale'
        ($ruleLines -join "`n") | Should-NotMatchString 'Remove-NetFirewallRule.*PreRemoved'
    }

    It 'generates NRPT remove, update, add, and unchanged command branches' {
        $currentRule = New-NRFixtureNrptRuleRecord -Id 'existing' -Server '192.0.2.1'
        $updatedRule = New-NRFixtureNrptRuleRecord -Id 'existing' -Server '192.0.2.2'
        $newRule = New-NRFixtureNrptRuleRecord -Id 'new' -Server '192.0.2.3'
        $lines = New-Object 'System.Collections.Generic.List[string]'
        $desired = [pscustomobject]@{ nrptRules = @($updatedRule, $newRule) }
        $snapshot = [pscustomobject]@{ nrptRules = @($currentRule, (New-NRFixtureNrptRuleRecord -Id 'stale')) }
        Invoke-NRPrivateFunction -Name Add-NRGeneratedNrptCommands -Parameters @{
            Lines = $lines; Desired = $desired; SnapshotConfiguration = $snapshot
        }
        ($lines -join "`n") | Should-MatchString 'Remove-DnsClientNrptRule'
        ($lines -join "`n") | Should-MatchString 'Add-DnsClientNrptRule'
        ($lines -join "`n") | Should-MatchString 'existing'
        ($lines -join "`n") | Should-MatchString 'new'

        $lines.Clear()
        Invoke-NRPrivateFunction -Name Add-NRGeneratedNrptCommands -Parameters @{
            Lines = $lines; Desired = ([pscustomobject]@{ nrptRules = @($currentRule) });
            SnapshotConfiguration = ([pscustomobject]@{ nrptRules = @($currentRule) })
        }
        ($lines -join "`n") | Should-NotMatchString 'Add-DnsClientNrptRule'
        ($lines -join "`n") | Should-NotMatchString 'Remove-DnsClientNrptRule'
    }

    It 'handles Generate default output path, existing output, Force, missing directory, WhatIf, and computer mismatch' {
        $path = Join-Path $TestDrive 'generate-default-name.json'
        $configuration = New-NRFixtureConfiguration
        Write-NRJsonFile -Path $path -InputObject $configuration
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $configuration)
        Write-NRStateFile -Path (Get-NRStatePath -Path $path) -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('AllowHttps') })

        $defaultOutput = Join-Path $TestDrive 'generate-default-name.generate.ps1'
        $previousWhatIfPreference = $WhatIfPreference
        $previousConfirmPreference = $ConfirmPreference
        try {
            # Isolate this test from inherited ShouldProcess preferences so
            # the invocation always exercises the file-writing branch.
            $WhatIfPreference = $false
            $ConfirmPreference = 'None'
            $generateOutput = @(Invoke-NRGenerate -Path $path -Confirm:$false -WhatIf:$false)
        }
        finally {
            $WhatIfPreference = $previousWhatIfPreference
            $ConfirmPreference = $previousConfirmPreference
        }
        ($generateOutput -join [Environment]::NewLine) | Should-MatchString ([regex]::Escape($defaultOutput))
        (Test-Path -LiteralPath $defaultOutput -PathType Leaf) | Should-Be $true
        { Invoke-NRGenerate -Path $path } | Should-Throw -ExceptionMessage '*already exists*'
        Set-Content -LiteralPath $defaultOutput -Value 'old content'
        Invoke-NRGenerate -Path $path -Force -Confirm:$false | Out-Null
        (Get-Content -LiteralPath $defaultOutput -Raw) | Should-MatchString 'Generated by PSNetRules generate'

        $whatIfPath = Join-Path $TestDrive 'generate-whatif.ps1'
        Invoke-NRGenerate -Path $path -OutputPath $whatIfPath -WhatIf | Out-Null
        (Test-Path -LiteralPath $whatIfPath) | Should-Be $false

        $missingDirectoryPath = Join-Path (Join-Path $TestDrive 'missing-output-dir') 'script.ps1'
        { Invoke-NRGenerate -Path $path -OutputPath $missingDirectoryPath } |
            Should-Throw -ExceptionMessage '*Output directory does not exist*'

        $wrongSnapshot = New-NRFixtureCaptureSnapshot -Configuration $configuration
        $wrongSnapshot.computerName = 'OTHER-COMPUTER'
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $wrongSnapshot
        { Invoke-NRGenerate -Path $path -OutputPath (Join-Path $TestDrive 'wrong-computer.ps1') } |
            Should-Throw -ExceptionMessage '*not*'
    }

}


Describe 'PSCustomObject diff property ordering' {
    It 'preserves Sort-Object ordering while combining before and after properties' {
        $before = [pscustomobject][ordered]@{ Zebra = 1; alpha = 1; Delta = 1 }
        $after = [pscustomobject][ordered]@{ BETA = 2; ALPHA = 3; gamma = 4 }
        $expectedNames = @(@($before.PSObject.Properties.Name) + @($after.PSObject.Properties.Name) | Sort-Object -Unique)
        $actualNames = @(Invoke-NRPrivateFunction -Name Get-NRPCustomObjectPropertyNames -Parameters @{
            Before = $before
            After = $after
        })

        $actualNames | Should-BeCollection $expectedNames
    }

    It 'returns no property names when both sides are null' {
        $names = @(Invoke-NRPrivateFunction -Name Get-NRPCustomObjectPropertyNames -Parameters @{
            Before = $null
            After = $null
        })
        $names.Count | Should-Be 0
    }
}

Describe 'diff comparison compatibility and complexity coverage' {
    It 'covers adapted objects and the general dictionary diff fallback' {
        $fileInfo = New-Object System.IO.FileInfo -ArgumentList (Join-Path $TestDrive 'comparison-probe.txt')
        (Invoke-NRPrivateFunction -Name Test-NRObjectLike -Parameters @{ Value = $fileInfo }) | Should-Be $true

        $before = @{
            Changed = 'old'
            Removed = 'value'
            Nested = @{ RemovedNested = 'old'; Retained = 1 }
            Retained = 'same'
        }
        $after = @{
            Changed = 'new'
            Added = 'value'
            Nested = @{ AddedNested = 'new'; Retained = 1 }
            Retained = 'same'
        }
        $details = @(Invoke-NRPrivateFunction -Name Get-NRObjectChanges -Parameters @{ Before = $before; After = $after })
        $details.Count | Should-Be 5
        ($details -join "`n") | Should-MatchString '(?m)^Changed:'
        ($details -join "`n") | Should-MatchString '(?m)^Added:'
        ($details -join "`n") | Should-MatchString 'Nested\.AddedNested:'
        ($details -join "`n") | Should-MatchString 'Nested\.RemovedNested:'
        ($details -join "`n") | Should-MatchString '(?m)^Removed:'
        ($details -join "`n") | Should-NotMatchString 'Retained:'
    }

    It 'handles null sides in the PSCustomObject comparison path' {
        $added = @(Invoke-NRPrivateFunction -Name Get-NRObjectChanges -Parameters @{
            Before = $null; After = [pscustomobject]@{ Added = 'value' }
        })
        $removed = @(Invoke-NRPrivateFunction -Name Get-NRObjectChanges -Parameters @{
            Before = [pscustomobject]@{ Removed = 'value' }; After = $null
        })
        $empty = @(Invoke-NRPrivateFunction -Name Get-NRObjectChanges -Parameters @{ Before = $null; After = $null })
        $added.Count | Should-Be 1
        $removed.Count | Should-Be 1
        $empty.Count | Should-Be 0
        $added[0] | Should-MatchString '^Added:'
        $removed[0] | Should-MatchString '^Removed:'
    }

    It 'covers string-sequence count, fallback, null and multiset mismatch branches' {
        $leftList = New-Object System.Collections.ArrayList
        $rightList = New-Object System.Collections.ArrayList
        [void]$leftList.Add('one')
        [void]$rightList.Add('one')
        [void]$rightList.Add('two')
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = $leftList; Right = $rightList }) | Should-Be $false

        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('one', 1); Right = @('one', '1') }) | Should-Be $null
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('one'); Right = @('one', 1) }) | Should-Be $null
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('one'); Right = @('one', [pscustomobject]@{ Value = 'two' }) }) | Should-Be $null
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @($null, 'one'); Right = @('two', 'one') }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @($null, 'one'); Right = @('one', $null) }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @(); Right = @() }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('one', 'one'); Right = @('one', 'two') }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('one', 'two'); Right = @('one', 'three') }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('one', 'one', 'two'); Right = @('one', 'two', 'two') }) | Should-Be $false
    }

    It 'covers comparison conversion dictionaries and both default-field representations' {
        $plain = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonPlainValue -Parameters @{ Value = @{ z = 2; a = 'one' } }
        $plain['a'] | Should-Be 'one'
        $plain['z'] | Should-Be 2

        $persistentPscustom = @{
            'Rule-PsCustom' = [pscustomobject]@{
                IsComplete = $true
                Fields = [pscustomobject]@{ Field = [pscustomobject]@{ Value = 'value' } }
            }
        }
        $defaultsPscustom = @{
            'Rule-PsCustom' = [pscustomobject]@{
                IsComplete = $true
                Fields = [pscustomobject]@{ Field = [pscustomobject]@{ Value = 'value' } }
            }
        }
        (Get-NRDefaultRuleStatus -Name 'Rule-PsCustom' -PersistentComparisonByName $persistentPscustom -SystemDefaultsByName $defaultsPscustom) | Should-Be 'ExactMatch'

        $persistentDictionary = @{
            'Rule-Dictionary' = @{ IsComplete = $true; Fields = @{ Field = @{ Value = 'value' } } }
        }
        $defaultsDictionary = @{
            'Rule-Dictionary' = @{ IsComplete = $true; Fields = @{ Field = @{ Value = 'value' } } }
        }
        (Get-NRDefaultRuleStatus -Name 'Rule-Dictionary' -PersistentComparisonByName $persistentDictionary -SystemDefaultsByName $defaultsDictionary) | Should-Be 'ExactMatch'
        $defaultsDictionary['Rule-Dictionary'].Fields.Field.Value = 'different'
        (Get-NRDefaultRuleStatus -Name 'Rule-Dictionary' -PersistentComparisonByName $persistentDictionary -SystemDefaultsByName $defaultsDictionary) | Should-Be 'Mismatch'
        $defaultsDictionary['Rule-Dictionary'].Fields = @{ Other = @{ Value = 'value' } }
        (Get-NRDefaultRuleStatus -Name 'Rule-Dictionary' -PersistentComparisonByName $persistentDictionary -SystemDefaultsByName $defaultsDictionary) | Should-Be 'Mismatch'
    }

    It 'covers extracted validation and comparison helpers' {
        $counts = New-Object 'System.Collections.Generic.Dictionary[string, int]' ([System.StringComparer]::Ordinal)
        $counts.Add('remaining', 1)
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceCountsEmpty -Parameters @{ Counts = $counts }) | Should-Be $false

        $map = Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{
            Items = @(@{ id = 'dictionary-item' }, @{ id = 'second-dictionary-item'; other = 'extra-value' }); KeyProperty = 'id'
        }
        $map.Count | Should-Be 2
        $map['dictionary-item'].id | Should-Be 'dictionary-item'
        $map['second-dictionary-item'].other | Should-Be 'extra-value'
        { Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{ Items = @(@{ other = 'missing' }); KeyProperty = 'id' } } |
            Should-Throw -ExceptionMessage "*empty 'id'*"

        $configuration = @{ firewallRules = @() }
        Invoke-NRPrivateFunction -Name Set-NRExcludedFirewallRuleNames -Parameters @{
            Configuration = $configuration; Names = @('Rule-B', 'Rule-A', 'Rule-A')
        } | Out-Null
        $configuration.excludedFirewallRules | Should-BeCollection @('Rule-A', 'Rule-B')

        (Invoke-NRPrivateFunction -Name Get-NRComparisonFieldValue -Parameters @{ Field = $null }) | Should-Be $null
        (Invoke-NRPrivateFunction -Name Get-NRComparisonFieldValue -Parameters @{ Field = [pscustomobject]@{ Value = 'payload' } }) |
            Should-Be 'payload'

        $persistent = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $true } }
        $defaults = @{ 'Rule-A' = [pscustomobject]@{ IsComplete = $true } }
        (Get-NRDefaultRuleStatus -Name 'Rule-A' -PersistentComparisonByName $persistent -SystemDefaultsByName $defaults) |
            Should-Be 'ExactMatch'

        $before = [pscustomobject]@{ Child = [pscustomobject]@{ Value = 1 }; Scalar = 'same' }
        $after = [pscustomobject]@{ Child = [pscustomobject]@{ Value = 2 }; Scalar = 'same' }
        $changes = @(Invoke-NRPrivateFunction -Name Get-NRObjectChanges -Parameters @{ Before = $before; After = $after })
        $changes.Count | Should-Be 1
        $changes[0] | Should-MatchString 'Child.Value'

        (Invoke-NRPrivateFunction -Name Test-NRValueOnlyComparisonFieldsEqual -Parameters @{
            PersistentField = [pscustomobject]@{ Value = 'same' }; DefaultField = [pscustomobject]@{ Value = 'same' }
        }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRValueOnlyComparisonFieldsEqual -Parameters @{
            PersistentField = [pscustomobject]@{ Value = 'left' }; DefaultField = [pscustomobject]@{ Value = 'right' }
        }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRValueOnlyComparisonFieldsEqual -Parameters @{
            PersistentField = [pscustomobject]@{ Other = 'same' }; DefaultField = [pscustomobject]@{ Other = 'same' }
        }) | Should-Be $null
    }

    It 'validates field values on adapted .NET objects and skips non-property comparison members' {
        $uri = [uri]::new('https://example.test/path')
        Invoke-NRPrivateFunction -Name Assert-NRFieldType -Parameters @{
            Object = $uri; Field = 'Host'; Kind = 'string'; Context = 'uri'
        }

        $source = [pscustomobject]@{ DisplayName = 'Rule A'; Enabled = $true }
        Add-Member -InputObject $source -MemberType ScriptProperty -Name Computed -Value { 'ignored' }
        $fields = Invoke-NRPrivateFunction -Name Get-NRComparisonProperties -Parameters @{
            InputObject = $source; Section = 'Rule'
        }
        $fields.ContainsKey('Rule.DisplayName') | Should-Be $true
        $fields.ContainsKey('Rule.Enabled') | Should-Be $true
        $fields.ContainsKey('Rule.Computed') | Should-Be $false
    }

}


Describe 'netrules remaining coverage paths' {
    It 'covers object-like property values and comparison-field fallback shapes' {
        (Invoke-NRPrivateFunction -Name Test-NRPropertyValueObjectLike -Parameters @{ Value = @{ Child = 'value' } }) |
            Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRPropertyValueObjectLike -Parameters @{ Value = [pscustomobject]@{} }) |
            Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRPropertyValueObjectLike -Parameters @{ Value = [uri]::new('https://example.test/path') }) |
            Should-Be $true

        (Invoke-NRPrivateFunction -Name Get-NRComparisonFieldValue -Parameters @{
            Field = [pscustomobject]@{ Other = 'no-value-member' }
        }) | Should-Be $null
        (Invoke-NRPrivateFunction -Name Test-NRValueOnlyComparisonFieldsEqual -Parameters @{
            PersistentField = @{ Value = 'same' }; DefaultField = [pscustomobject]@{ Value = 'same' }
        }) | Should-Be $null

        $persistentFields = [pscustomobject]@{ Field = @{ Value = 'left' } }
        $defaultFields = [pscustomobject]@{ Field = @{ Value = 'right' } }
        (Invoke-NRPrivateFunction -Name Test-NRPCustomObjectComparisonFieldsEqual -Parameters @{
            PersistentFields = $persistentFields; DefaultFields = $defaultFields
        }) | Should-Be $false

        (Invoke-NRPrivateFunction -Name Get-NRComparisonEntryFields -Parameters @{ Entry = $null }) |
            Should-Be $null
        (Invoke-NRPrivateFunction -Name Get-NRComparisonEntryFields -Parameters @{
            Entry = [pscustomobject]@{ Other = 'no-fields-member' }
        }) | Should-Be $null
    }

    It 'rejects a PSCustomObject keyed-map item without the requested property' {
        $item = [pscustomobject]@{ other = 'missing' }
        { Invoke-NRPrivateFunction -Name Get-NRMapByKey -Parameters @{ Items = @($item); KeyProperty = 'id' } } |
            Should-Throw -ExceptionMessage "*empty 'id'*"
    }

    It 'retains unrelated classifications when adding a unique Rename classification' {
        $oldRule = New-NRFixtureFirewallRuleRecord -Name 'Old-Rule' -DisplayName 'Same Application'
        $newRule = New-NRFixtureFirewallRuleRecord -Name 'New-Rule' -DisplayName 'Same Application'
        $unrelated = [pscustomobject]@{ Name = 'Unrelated-Rule'; Status = 'ExactMatch'; Management = 'Managed' }
        $classifications = @(
            [pscustomobject]@{ Name = 'Old-Rule'; Status = 'Missing'; SystemDefaults = 'NotFound' },
            [pscustomobject]@{ Name = 'New-Rule'; Status = 'NewCandidate'; SystemDefaults = 'NotFound' },
            $unrelated
        )

        $results = @(Invoke-NRPrivateFunction -Name Add-NRFirewallRuleRenameClassifications -Parameters @{
            Classifications = $classifications
            DesiredByName = @{ 'Old-Rule' = $oldRule }
            CurrentByName = @{ 'New-Rule' = $newRule }
        })

        $results.Count | Should-Be 2
        @($results | Where-Object Status -eq 'Rename').Count | Should-Be 1
        @($results | Where-Object { $_.Name -eq 'Unrelated-Rule' }).Count | Should-Be 1
    }

    It 'covers managed-name rejection and empty Rename source selection' {
        { Invoke-NRPrivateFunction -Name Assert-NRAdoptNamedRule -Parameters @{
            Name = 'Rule-A'; Update = $false
            CurrentByName = @{ 'Rule-A' = New-NRFixtureFirewallRuleRecord -Name 'Rule-A' }
            DesiredByName = @{}; Managed = @{ 'Rule-A' = $true }
            Classifications = @([pscustomobject]@{ Name = 'Rule-A'; Status = 'NewCandidate' })
        } } | Should-Throw -ExceptionMessage '*already managed*'

        $renames = @([pscustomobject]@{ OldName = 'Old-A'; NewName = 'New-A'; Status = 'Rename' })
        { Invoke-NRPrivateFunction -Name Get-NRAdoptRenameSelection -Parameters @{
            Names = @(''); Classifications = $renames
        } } | Should-Throw -ExceptionMessage '*Rename source Name cannot be empty*'
    }

    It 'rejects invalid Rename records and a Rename whose new name is absent from the snapshot' {
        $rename = [pscustomobject]@{ OldName = 'Old-Rule'; NewName = 'New-Rule' }
        $currentRule = New-NRFixtureFirewallRuleRecord -Name 'New-Rule'
        $state = [pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @('Old-Rule') }

        $duplicateOldRecords = New-Object 'System.Collections.Generic.List[object]'
        $duplicateOldRecords.Add([pscustomobject]@{ name = 'Old-Rule' })
        $duplicateOldRecords.Add([pscustomobject]@{ name = 'Old-Rule' })
        { Invoke-NRPrivateFunction -Name Set-NRAdoptedRenameRule -Parameters @{
            Records = $duplicateOldRecords; State = $state; Rename = $rename; CurrentRule = $currentRule
        } } | Should-Throw -ExceptionMessage '*duplicate old Rename name*'

        $conflictingNewRecords = New-Object 'System.Collections.Generic.List[object]'
        $conflictingNewRecords.Add([pscustomobject]@{ name = 'Old-Rule' })
        $conflictingNewRecords.Add([pscustomobject]@{ name = 'New-Rule' })
        { Invoke-NRPrivateFunction -Name Set-NRAdoptedRenameRule -Parameters @{
            Records = $conflictingNewRecords; State = $state; Rename = $rename; CurrentRule = $currentRule
        } } | Should-Throw -ExceptionMessage '*new Name is already present*'

        $missingOldRecords = New-Object 'System.Collections.Generic.List[object]'
        $missingOldRecords.Add([pscustomobject]@{ name = 'Other-Rule' })
        { Invoke-NRPrivateFunction -Name Set-NRAdoptedRenameRule -Parameters @{
            Records = $missingOldRecords; State = $state; Rename = $rename; CurrentRule = $currentRule
        } } | Should-Throw -ExceptionMessage '*old Name is no longer in Desired State*'

        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @((New-NRFixtureFirewallRuleRecord -Name 'Old-Rule'))
        { Invoke-NRPrivateFunction -Name Set-NRAdoptedRenameConfiguration -Parameters @{
            Desired = $desired; State = $state; Renames = @($rename); CurrentByName = @{}
        } } | Should-Throw -ExceptionMessage '*new Name is no longer in the latest Snapshot*'
    }

    It 'keeps unrelated excluded names after adopting a selected Firewall rule' {
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @()
        $desired.excludedFirewallRules = @('Selected-Rule', 'Keep-Excluded-Rule')
        $state = [pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() }
        $selectedRule = New-NRFixtureFirewallRuleRecord -Name 'Selected-Rule'

        $updated = Invoke-NRPrivateFunction -Name Set-NRAdoptedConfiguration -Parameters @{
            Desired = $desired; State = $state; Names = @('Selected-Rule')
            CurrentByName = @{ 'Selected-Rule' = $selectedRule }; Update = $false
        }

        @($updated.Desired.excludedFirewallRules) | Should-BeCollection @('Keep-Excluded-Rule')
        @($updated.State.managedFirewallRules) | Should-BeCollection @('Selected-Rule')
    }

    It 'reports missing State backups and failed State cleanup during rollback' {
        $configurationBackup = Join-Path $TestDrive 'rollback-config-backup.json'
        $configurationPath = Join-Path $TestDrive 'rollback-config.json'
        $statePath = Join-Path $TestDrive 'rollback-state.json'
        [System.IO.File]::WriteAllText($configurationBackup, 'original configuration')
        [System.IO.File]::WriteAllText($statePath, 'partial state')

        $missingBackupErrors = @(Invoke-NRPrivateFunction -Name Restore-NRUnmanageFiles -Parameters @{
            ConfigurationPath = $configurationPath; ConfigurationBackup = $configurationBackup
            StatePath = $statePath; StateBackup = $null; StateExisted = $true
        })
        $missingBackupErrors.Count | Should-Be 1
        $missingBackupErrors[0] | Should-MatchString 'State backup path is unavailable'

        Mock Remove-Item -ModuleName PSNetRules { throw 'Injected State cleanup failure.' }
        $cleanupErrors = @(Invoke-NRPrivateFunction -Name Restore-NRUnmanageFiles -Parameters @{
            ConfigurationPath = $configurationPath; ConfigurationBackup = $configurationBackup
            StatePath = $statePath; StateBackup = $null; StateExisted = $false
        })
        $cleanupErrors.Count | Should-Be 1
        $cleanupErrors[0] | Should-MatchString 'state cleanup: Injected State cleanup failure'
        Should-Invoke Remove-Item -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'removes staged files and rethrows when State serialization fails' {
        $configurationPath = Join-Path $TestDrive 'staged-config.json'
        $statePath = Join-Path $TestDrive 'staged-state.json'
        $updated = [pscustomobject]@{
            Desired = New-NRFixtureConfiguration
            State = [pscustomobject]@{ schemaVersion = 1; nrptRules = @{}; managedFirewallRules = @() }
        }
        Mock Write-NRStateFile -ModuleName PSNetRules { throw 'Injected State serialization failure.' }

        { Invoke-NRPrivateFunction -Name New-NRUnmanageStagedFiles -Parameters @{
            ConfigurationPath = $configurationPath; StatePath = $statePath; Updated = $updated
        } } | Should-Throw -ExceptionMessage '*Injected State serialization failure*'

        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.unmanage.*.tmp' -File).Count | Should-Be 0
        Should-Invoke Write-NRStateFile -ModuleName PSNetRules -Times 1 -Exactly
    }

    It 'returns the path of a pre-apply backup' {
        $backup = Invoke-NRPrivateFunction -Name New-NRBackup -Parameters @{
            ConfigurationPath = (Join-Path $TestDrive 'return-backup.json')
            CurrentState = (New-NRFixtureConfiguration)
            State = $null
        }

        $backup | Should-MatchString '\.pre-apply\.\d{8}-\d{6}-\d{3}\.json$'
        Test-Path -LiteralPath $backup -PathType Leaf | Should-Be $true
    }
}

Describe 'netrules search command' {
    BeforeAll {
        function New-NRSearchFixtureSnapshotEntry {
            param(
                [string] $Name = 'SqlRule',
                [string] $Program = 'C:\Apps\sql.exe'
            )
            $fields = @{}
            $fields['Rule.DisplayName'] = [pscustomobject]@{ Value = 'Allow SQL Server' }
            $fields['Rule.Description'] = [pscustomobject]@{ Value = '' }
            $fields['Rule.Group'] = [pscustomobject]@{ Value = '' }
            $fields['Rule.Enabled'] = [pscustomobject]@{ Value = 'True' }
            $fields['Rule.Profile'] = [pscustomobject]@{ Value = 'Private' }
            $fields['Rule.Direction'] = [pscustomobject]@{ Value = 'Inbound' }
            $fields['Rule.Action'] = [pscustomobject]@{ Value = 'Allow' }
            $fields['Address.LocalAddress'] = [pscustomobject]@{ Value = @('Any') }
            $fields['Address.RemoteAddress'] = [pscustomobject]@{ Value = @('10.0.0.0/24') }
            $fields['Application.AppPath'] = [pscustomobject]@{ Value = $Program }
            $fields['Application.Package'] = [pscustomobject]@{ Value = 'Any' }
            $fields['Port.Protocol'] = [pscustomobject]@{ Value = 'TCP' }
            $fields['Port.LocalPort'] = [pscustomobject]@{ Value = @('1433') }
            $fields['Port.DynamicTransport'] = [pscustomobject]@{ Value = 'Any' }
            $fields['Port.RemotePort'] = [pscustomobject]@{ Value = @('Any') }
            $fields['Service.ServiceName'] = [pscustomobject]@{ Value = 'MSSQLSERVER' }
            $fields['Security.LocalUsers'] = [pscustomobject]@{ Value = 'O:LSD:(A;;CC;;;S-1-5-18)' }
            $fields['Security.RemoteUsers'] = [pscustomobject]@{ Value = 'Any' }
            $fields['Security.RemoteMachines'] = [pscustomobject]@{ Value = 'Any' }
            return [pscustomobject]@{ Name = $Name; IsComplete = $true; MissingFilters = @(); FilterIssues = @(); Fields = $fields }
        }

        function New-NRSearchFixtureSnapshot {
            param([object[]] $Entries)
            return [pscustomobject][ordered]@{
                schemaVersion = 1
                capturedAt = (Get-Date).ToString('o')
                computerName = $env:COMPUTERNAME
                configuration = (New-NRFixtureConfiguration)
                comparison = [pscustomobject]@{
                    persistentStore = [pscustomobject]@{ PolicyStore = 'PersistentStore'; RuleCount = $Entries.Count; Entries = $Entries; BulkFilterWarnings = @() }
                    systemDefaults = [pscustomobject]@{ PolicyStore = 'SystemDefaults'; RuleCount = 0; Entries = @(); BulkFilterWarnings = @() }
                }
            }
        }
    }

    It 'unwraps snapshot comparison entries and deduplicates by Name' {
        $snapshot = New-NRSearchFixtureSnapshot -Entries @(
            (New-NRSearchFixtureSnapshotEntry -Name 'SqlRule'),
            (New-NRSearchFixtureSnapshotEntry -Name 'SqlRule'),
            (New-NRSearchFixtureSnapshotEntry -Name 'OtherRule')
        )
        $rules = @(Get-NRSearchableFirewallRule -Source Snapshot -Snapshot $snapshot)
        $rules.Count | Should-Be 2
        $rules[0].Name | Should-Be 'SqlRule'
        $rules[0].Fields['Rule.Direction'] | Should-Be 'Inbound'
        $rules[0].Fields['Application.Program'] | Should-Be 'C:\Apps\sql.exe'
        $rules[0].Fields['Port.LocalPort'][0] | Should-Be '1433'
        $rules[0].Fields['Port.DynamicTarget'] | Should-Be 'Any'
        $rules[0].Fields['Service.Service'] | Should-Be 'MSSQLSERVER'
        $rules[0].Fields['Security.LocalUser'] | Should-Be 'O:LSD:(A;;CC;;;S-1-5-18)'
    }

    It 'normalizes desired-state records into the same field shape' {
        $desired = New-NRFixtureConfiguration
        $rules = @(Get-NRSearchableFirewallRule -Source Desired -Desired $desired)
        $rules.Count | Should-Be 1
        $rules[0].Name | Should-Be 'AllowHttps'
        $rules[0].Fields['Rule.Direction'] | Should-Be 'Inbound'
        $rules[0].Fields['Application.Program'] | Should-Be 'Any'
        $rules[0].Fields['Port.LocalPort'][0] | Should-Be '443'
        $rules[0].Fields['Security.LocalUser'] | Should-Be 'Any'
    }

    It 'matches direction and action exactly and combines conditions with AND' {
        $snapshot = New-NRSearchFixtureSnapshot -Entries @((New-NRSearchFixtureSnapshotEntry))
        $rule = @(Get-NRSearchableFirewallRule -Source Snapshot -Snapshot $snapshot)[0]
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Direction = @('Inbound'); Action = @('Allow') })) | Should-Be $true
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Direction = @('Outbound') })) | Should-Be $false
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Direction = @('Inbound'); Action = @('Block') })) | Should-Be $false
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{})) | Should-Be $true
    }

    It 'matches text across all fields and ports by exact element' {
        $snapshot = New-NRSearchFixtureSnapshot -Entries @((New-NRSearchFixtureSnapshotEntry))
        $rule = @(Get-NRSearchableFirewallRule -Source Snapshot -Snapshot $snapshot)[0]
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Text = 'sql' })) | Should-Be $true
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Text = 'MSSQLSERVER' })) | Should-Be $true
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Text = 'oracle' })) | Should-Be $false
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ LocalPort = @('1433') })) | Should-Be $true
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ LocalPort = @('143') })) | Should-Be $false
    }

    It 'matches SID substrings, name patterns, and the Enabled state' {
        $snapshot = New-NRSearchFixtureSnapshot -Entries @((New-NRSearchFixtureSnapshotEntry))
        $rule = @(Get-NRSearchableFirewallRule -Source Snapshot -Snapshot $snapshot)[0]
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Sid = 'S-1-5-18' })) | Should-Be $true
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Sid = 'S-1-5-19' })) | Should-Be $false
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ NamePattern = 'sql' })) | Should-Be $true
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ NamePattern = 'server' })) | Should-Be $true
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Enabled = $true })) | Should-Be $true
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Enabled = $false })) | Should-Be $false
    }

    It 'classifies program path states for the missing-program search' {
        (Test-NRProgramPathState -Program '') | Should-Be 'NotApplicable'
        (Test-NRProgramPathState -Program 'Any') | Should-Be 'NotApplicable'
        (Test-NRProgramPathState -Program 'sql.exe') | Should-Be 'Unverifiable'
        (Test-NRProgramPathState -Program '%SystemRoot%\System32\sql.exe') | Should-Be 'Unverifiable'
        $existing = Join-Path $TestDrive 'existing-app.exe'
        [System.IO.File]::WriteAllText($existing, 'x')
        (Test-NRProgramPathState -Program $existing) | Should-Be 'Exists'
        (Test-NRProgramPathState -Program (Join-Path $TestDrive 'missing-app.exe')) | Should-Be 'Missing'
    }

    It 'searches the snapshot and desired state end to end' {
        $path = Join-Path $TestDrive 'search.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        $snapshot = New-NRSearchFixtureSnapshot -Entries @((New-NRSearchFixtureSnapshotEntry))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $snapshot

        $snapshotOutput = @(Invoke-NRSearch -Path $path -Direction Inbound -Action Allow) -join [Environment]::NewLine
        $snapshotOutput | Should-MatchString 'SqlRule'
        $snapshotOutput | Should-MatchString '1 matched'
        $noMatchOutput = @(Invoke-NRSearch -Path $path -Direction Outbound) -join [Environment]::NewLine
        $noMatchOutput | Should-MatchString '0 matched'
        $desiredOutput = @(Invoke-NRSearch -Path $path -Source Desired -LocalPort '443') -join [Environment]::NewLine
        $desiredOutput | Should-MatchString 'AllowHttps'
        { Invoke-NRSearch -Path $path -Enabled -Disabled } | Should-Throw
    }

    It 'extracts rules whose program file is missing and skips blank or Any programs' {
        $path = Join-Path $TestDrive 'search-missing.json'
        $desired = New-NRFixtureConfiguration
        $stale = New-NRFixtureFirewallRuleRecord -Name 'StaleRule'
        $stale.filters.application.Program = Join-Path $TestDrive 'gone.exe'
        $desired.firewallRules = @($stale, (New-NRFixtureFirewallRuleRecord -Name 'AnyProgramRule'))
        Write-NRJsonFile -Path $path -InputObject $desired

        $output = @(Invoke-NRSearch -Path $path -Source Desired -MissingProgram) -join [Environment]::NewLine
        $output | Should-MatchString 'StaleRule'
        $output | Should-MatchString 'Missing'
        $output | Should-MatchString '1 matched'
    }

    It 'extracts snapshot rules whose program file is missing through the CIM AppPath field' {
        $path = Join-Path $TestDrive 'search-missing-snapshot.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        $snapshot = New-NRSearchFixtureSnapshot -Entries @(
            (New-NRSearchFixtureSnapshotEntry -Name 'StaleSnapshotRule' -Program 'C:\Apps\gone.exe'),
            (New-NRSearchFixtureSnapshotEntry -Name 'AnyProgramRule' -Program 'Any')
        )
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $snapshot

        $output = @(Invoke-NRSearch -Path $path -MissingProgram) -join [Environment]::NewLine
        $output | Should-MatchString 'StaleSnapshotRule'
        $output | Should-MatchString 'Missing'
        $output | Should-MatchString '1 matched'
        $byProgram = @(Invoke-NRSearch -Path $path -Program 'gone') -join [Environment]::NewLine
        $byProgram | Should-MatchString 'StaleSnapshotRule'
        $byProgram | Should-MatchString '1 matched'
    }

    It 'fails when the snapshot has not been captured' {
        $path = Join-Path $TestDrive 'search-nosnapshot.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        { Invoke-NRSearch -Path $path } | Should-Throw '*Run capture first*'
    }

    It 'covers the search helper branches directly' {
        (ConvertTo-NRSearchText -Value $null) | Should-Be ''
        (ConvertTo-NRSearchText -Value 'abc') | Should-Be 'abc'
        (ConvertTo-NRSearchText -Value @('a', 'b')) | Should-Be 'a b'
        (ConvertTo-NRSearchText -Value ([pscustomobject]@{ A = 1 })) | Should-Be '{"A":1}'

        (Test-NRSearchValueContains -Value 'hello' -Pattern 'ell') | Should-Be $true
        (Test-NRSearchValueContains -Value 'hello' -Pattern 'xyz') | Should-Be $false
        (Test-NRSearchFieldContains -Fields @{} -Name 'Rule.Direction' -Pattern 'In') | Should-Be $false

        (Test-NRSearchFieldHasExactValue -Fields @{} -Name 'Port.LocalPort' -Values @('1433')) | Should-Be $false
        (Test-NRSearchFieldHasExactValue -Fields @{ 'Port.LocalPort' = '1433' } -Name 'Port.LocalPort' -Values @('1433')) | Should-Be $true
        (Test-NRSearchFieldHasExactValue -Fields @{ 'Port.LocalPort' = @('80', '443') } -Name 'Port.LocalPort' -Values @('443')) | Should-Be $true
        (Test-NRSearchFieldHasExactValue -Fields @{ 'Port.LocalPort' = @('80', '443') } -Name 'Port.LocalPort' -Values @('22')) | Should-Be $false

        (Test-NRSearchExactCondition -Fields @{} -FieldName 'Rule.Direction' -Values @('Inbound')) | Should-Be $false
        (Test-NRSearchExactCondition -Fields @{} -FieldName 'Rule.Direction' -Values $null) | Should-Be $true

        $enabledQuery = [pscustomobject]@{ Enabled = $true }
        (Test-NRSearchEnabledCondition -Fields @{ 'Rule.Enabled' = $true } -Query $enabledQuery) | Should-Be $true
        (Test-NRSearchEnabledCondition -Fields @{ 'Rule.Enabled' = $false } -Query $enabledQuery) | Should-Be $false
        (Test-NRSearchEnabledCondition -Fields @{} -Query $enabledQuery) | Should-Be $false

        $programFields = @{ 'Application.Program' = 'C:\Apps\tool.exe' }
        (Test-NRSearchSubstringCondition -Fields $programFields -FieldName 'Application.Program' -Pattern 'tool') | Should-Be $true
        (Test-NRSearchSubstringCondition -Fields $programFields -FieldName 'Application.Program' -Pattern 'nomatch') | Should-Be $false
        (Test-NRSearchSubstringCondition -Fields $programFields -FieldName 'Application.Program' -Pattern $null) | Should-Be $true

        (Test-NRObjectLike -Value ([pscustomobject]@{})) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRPropertyValueObjectLike -Parameters @{ Value = [pscustomobject]@{} }) | Should-Be $false

        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @($null); Right = @($null) }) | Should-Be $true
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @($null); Right = @('a') }) | Should-Be $false
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @(1); Right = @(1) }) | Should-Be $null
        (Invoke-NRPrivateFunction -Name Test-NRStringSequenceEqual -Parameters @{ Left = @('a', 'b'); Right = @('a', 1) }) | Should-Be $null

        (Test-NRProgramPathState -Program 'C:\%APPDATA%\tool.exe') | Should-Be 'Unverifiable'
        (Test-NRProgramPathState -Program 'tool.exe') | Should-Be 'Unverifiable'
    }

    It 'rejects rules through each remaining matcher condition' {
        $rule = ConvertTo-NRSearchableSnapshotRule -Entry (New-NRSearchFixtureSnapshotEntry)
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Program = 'nomatch' })) | Should-Be $false
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ LocalPort = @('9999') })) | Should-Be $false
        (Test-NRFirewallRuleSearchMatch -Rule $rule -Query ([pscustomobject]@{ Sid = 'S-1-5-999' })) | Should-Be $false
    }

    It 'tolerates null entries and missing filter sections in search sources' {
        $snapshot = New-NRSearchFixtureSnapshot -Entries @($null, (New-NRSearchFixtureSnapshotEntry))
        @(Get-NRSearchableFirewallRule -Source Snapshot -Snapshot $snapshot).Count | Should-Be 1

        $desired = New-NRFixtureConfiguration
        $record = New-NRFixtureFirewallRuleRecord -Name 'PartialRule'
        $record.filters.PSObject.Properties.Remove('security')
        $desired.firewallRules = @($null, $record)
        $rules = @(Get-NRSearchableFirewallRule -Source Desired -Desired $desired)
        $rules.Count | Should-Be 1
        $rules[0].Fields.Contains('Security.LocalUser') | Should-Be $false
    }

    It 'formats results for rules without display names or summary fields' {
        $result = [pscustomobject]@{
            Rule = [pscustomobject]@{ Name = 'BareRule'; Fields = @{ 'Rule.Direction' = 'Inbound' } }
            ProgramState = $null
        }
        $lines = @(Format-NRSearchResults -Results @($result) -Source 'Desired')
        ($lines -join [Environment]::NewLine) | Should-MatchString 'BareRule'
        ($lines -join [Environment]::NewLine) | Should-MatchString 'Direction: Inbound'
    }

    It 'skips rules without a program when extracting missing programs' {
        $rule = [pscustomobject]@{ Name = 'NoProgramRule'; Fields = @{} }
        @(Get-NRSearchResults -Rules @($rule) -Query ([pscustomobject]@{}) -MissingProgram).Count | Should-Be 0
    }

    It 'filters by Enabled and Disabled end to end and validates its sources' {
        $path = Join-Path $TestDrive 'search-enabled.json'
        $desired = New-NRFixtureConfiguration
        $desired.firewallRules = @(
            (New-NRFixtureFirewallRuleRecord -Name 'EnabledRule' -Enabled 'True'),
            (New-NRFixtureFirewallRuleRecord -Name 'DisabledRule' -Enabled 'False')
        )
        Write-NRJsonFile -Path $path -InputObject $desired

        $enabledOutput = @(Invoke-NRSearch -Path $path -Source Desired -Enabled) -join [Environment]::NewLine
        $enabledOutput | Should-MatchString 'EnabledRule'
        $enabledOutput | Should-MatchString '1 matched'
        $disabledOutput = @(Invoke-NRSearch -Path $path -Source Desired -Disabled) -join [Environment]::NewLine
        $disabledOutput | Should-MatchString 'DisabledRule'
        $disabledOutput | Should-MatchString '1 matched'

        { Get-NRSearchSourceData -Source Desired -Path (Join-Path $TestDrive 'missing-desired.json') } | Should-Throw '*Desired-state file not found*'

        $foreign = New-NRSearchFixtureSnapshot -Entries @((New-NRSearchFixtureSnapshotEntry))
        $foreign.computerName = 'OTHER-PC-XYZ'
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject $foreign
        { Get-NRSearchSourceData -Source Snapshot -Path $path } | Should-Throw '*Snapshot belongs to computer*'
    }
}

Describe 'PSNetRules search through the command-line entry point' {
    It 'rejects search-only parameters outside search' {
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('diff', '-Text', 'sql')
        $result.ExitCode | Should-Be 1
        $result.StandardError | Should-MatchString '-Text is supported only by search'
    }

    It 'routes search to the desired state through the CLI' {
        $path = Join-Path $TestDrive 'entrypoint-search.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        $result = Invoke-NRRootScriptInChildProcess -Arguments @('search', '-Path', $path, '-Source', 'Desired', '-LocalPort', '443')
        Assert-NRChildProcessSuccess -Result $result -Context 'CLI search'
        $result.StandardOutput | Should-MatchString 'AllowHttps'
        $result.StandardOutput | Should-MatchString '1 matched'
    }
}

Describe 'PSNetRules NRPT adoption' {
    BeforeEach {
        Mock New-NRFileBackup -ModuleName PSNetRules { @() }
    }

    It 'adopts a captured NRPT rule under its GUID id without touching the state file' {
        Mock New-NRFileBackup -ModuleName PSNetRules { @('nrpt-backup-path') }
        $guid = '{F8B4324F-A698-4BBB-A153-12F651B64F2F}'
        $path = Join-Path $TestDrive 'adopt-nrpt.json'
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $captured = New-NRFixtureConfiguration
        $captured.nrptRules = @((New-NRFixtureNrptRuleRecord -Id $guid -Namespace @('.web.nhk') -Server '0.0.0.0' -DisplayName 'Block web.nhk'))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)
        $statePath = Get-NRStatePath -Path $path
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{ 'corp-dns' = '{11111111-2222-3333-4444-555555555555}' }; managedFirewallRules = @() })
        $stateBefore = Get-Content -LiteralPath $statePath -Raw

        $result = @(Invoke-NRAdopt -Path $path -Nrpt -Name $guid -Confirm:$false) -join [Environment]::NewLine

        $result | Should-MatchString 'NRPT rules to adopt: 1'
        $result | Should-MatchString 'Block web\.nhk'
        $result | Should-MatchString 'Backup: nrpt-backup-path'
        $result | Should-MatchString 'Adopted 1 NRPT rules\.'
        $rules = @((Read-NRConfiguration -Path $path).nrptRules)
        $rules.Count | Should-Be 1
        $rules[0].id | Should-Be $guid
        $rules[0].Namespace | Should-BeCollection @('.web.nhk')
        $rules[0].NameServers | Should-BeCollection @('0.0.0.0')
        $rules[0].DisplayName | Should-Be 'Block web.nhk'
        (Get-Content -LiteralPath $statePath -Raw) | Should-Be $stateBefore
    }

    It 'adopts multiple NRPT rules and keeps desired sorted by id' {
        $path = Join-Path $TestDrive 'adopt-nrpt-multi.json'
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $captured = New-NRFixtureConfiguration
        $captured.nrptRules = @(
            (New-NRFixtureNrptRuleRecord -Id '{BBBBBBBB-0000-0000-0000-000000000002}' -Namespace @('b.example')),
            (New-NRFixtureNrptRuleRecord -Id '{AAAAAAAA-0000-0000-0000-000000000001}' -Namespace @('a.example'))
        )
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)

        $result = @(Invoke-NRAdopt -Path $path -Nrpt -Name '{BBBBBBBB-0000-0000-0000-000000000002}', '{AAAAAAAA-0000-0000-0000-000000000001}', '{BBBBBBBB-0000-0000-0000-000000000002}' -Confirm:$false) -join [Environment]::NewLine

        $result | Should-MatchString 'Adopted 2 NRPT rules\.'
        $ids = @((Read-NRConfiguration -Path $path).nrptRules | ForEach-Object { $_.id })
        $ids | Should-BeCollection @('{AAAAAAAA-0000-0000-0000-000000000001}', '{BBBBBBBB-0000-0000-0000-000000000002}')
    }

    It 'updates an adopted NRPT rule from the latest capture' {
        $guid = '{F8B4324F-A698-4BBB-A153-12F651B64F2F}'
        $path = Join-Path $TestDrive 'adopt-nrpt-update.json'
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @((New-NRFixtureNrptRuleRecord -Id $guid -Namespace @('.web.nhk') -Server '0.0.0.0'))
        Write-NRJsonFile -Path $path -InputObject $desired
        $captured = New-NRFixtureConfiguration
        $captured.nrptRules = @((New-NRFixtureNrptRuleRecord -Id $guid -Namespace @('.web.nhk') -Server '127.0.0.1'))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)

        $result = @(Invoke-NRAdopt -Path $path -Nrpt -Update -Name $guid -Confirm:$false) -join [Environment]::NewLine

        $result | Should-MatchString 'NRPT rules to update: 1'
        $result | Should-MatchString 'Updated 1 NRPT rules\.'
        $rules = @((Read-NRConfiguration -Path $path).nrptRules)
        $rules.Count | Should-Be 1
        $rules[0].NameServers | Should-BeCollection @('127.0.0.1')
    }

    It 'rejects adopting an already managed NRPT rule without Update' {
        $guid = '{F8B4324F-A698-4BBB-A153-12F651B64F2F}'
        $path = Join-Path $TestDrive 'adopt-nrpt-duplicate.json'
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @((New-NRFixtureNrptRuleRecord -Id $guid))
        Write-NRJsonFile -Path $path -InputObject $desired
        $captured = New-NRFixtureConfiguration
        $captured.nrptRules = @((New-NRFixtureNrptRuleRecord -Id $guid))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)

        { Invoke-NRAdopt -Path $path -Nrpt -Name $guid -Confirm:$false } |
            Should-Throw "*NRPT rule '$guid' is already managed*"
    }

    It 'rejects updating an NRPT rule that is not managed' {
        $guid = '{F8B4324F-A698-4BBB-A153-12F651B64F2F}'
        $path = Join-Path $TestDrive 'adopt-nrpt-update-missing.json'
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $captured = New-NRFixtureConfiguration
        $captured.nrptRules = @((New-NRFixtureNrptRuleRecord -Id $guid))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)

        { Invoke-NRAdopt -Path $path -Nrpt -Update -Name $guid -Confirm:$false } |
            Should-Throw "*NRPT rule '$guid' is not currently managed*"
    }

    It 'rejects an NRPT id that is not in the capture snapshot' {
        $path = Join-Path $TestDrive 'adopt-nrpt-unknown.json'
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration))

        { Invoke-NRAdopt -Path $path -Nrpt -Name '{99999999-9999-9999-9999-999999999999}' -Confirm:$false } |
            Should-Throw "*is not present in the latest capture snapshot*"
    }

    It 'rejects bulk adoption, renaming, and a missing Name for NRPT rules' {
        $path = Join-Path $TestDrive 'adopt-nrpt-args.json'
        Write-NRJsonFile -Path $path -InputObject (New-NRFixtureConfiguration)
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration))

        { Invoke-NRAdopt -Path $path -Nrpt -New -Confirm:$false } |
            Should-Throw '*Bulk adoption (-New) is not supported for NRPT rules*'
        { Invoke-NRAdopt -Path $path -Nrpt -Rename -Name 'corp-dns' -Confirm:$false } |
            Should-Throw '*-Rename is not supported for NRPT rules*'
        { Invoke-NRAdopt -Path $path -Nrpt -Confirm:$false } |
            Should-Throw '*Adopting NRPT rules requires -Name*'
        { Invoke-NRAdopt -Path $path -Nrpt -Name '', 'corp-dns' -Confirm:$false } |
            Should-Throw '*NRPT rule id cannot be empty*'
    }

    It 'reports when there are no NRPT rules to adopt' {
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @()
        $snapshot = New-NRFixtureCaptureSnapshot -Configuration (New-NRFixtureConfiguration)

        $result = Invoke-NRPrivateFunction -Name Invoke-NRAdoptNrpt -Parameters @{
            Path = (Join-Path $TestDrive 'unused.json'); Desired = $desired
            Snapshot = $snapshot; Update = $false; Names = @()
        }

        $result | Should-Be 'No NRPT rules to adopt.'
    }

    It 'previews NRPT adoption with WhatIf without changing the desired file' {
        $guid = '{F8B4324F-A698-4BBB-A153-12F651B64F2F}'
        $path = Join-Path $TestDrive 'adopt-nrpt-whatif.json'
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @()
        Write-NRJsonFile -Path $path -InputObject $desired
        $captured = New-NRFixtureConfiguration
        $captured.nrptRules = @((New-NRFixtureNrptRuleRecord -Id $guid -Namespace @('.web.nhk') -Server '0.0.0.0'))
        Write-NRJsonFile -Path (Get-NRSnapshotPath -Path $path) -InputObject (New-NRFixtureCaptureSnapshot -Configuration $captured)
        $before = Get-Content -LiteralPath $path -Raw

        $result = @(Invoke-NRAdopt -Path $path -Nrpt -Name $guid -WhatIf) -join [Environment]::NewLine

        $result | Should-MatchString 'NRPT rules to adopt: 1'
        (Get-Content -LiteralPath $path -Raw) | Should-Be $before
    }

    It 'replaces only the selected records and sorts by id in the adopted NRPT configuration' {
        $desired = New-NRFixtureConfiguration
        $desired.nrptRules = @(
            (New-NRFixtureNrptRuleRecord -Id 'keep' -Namespace @('keep.example')),
            (New-NRFixtureNrptRuleRecord -Id 'refresh' -Namespace @('old.example'))
        )
        $current = @{
            'refresh' = (New-NRFixtureNrptRuleRecord -Id 'refresh' -Namespace @('new.example'))
            'added' = (New-NRFixtureNrptRuleRecord -Id 'added' -Namespace @('added.example'))
        }

        $updated = Invoke-NRPrivateFunction -Name Set-NRAdoptedNrptConfiguration -Parameters @{
            Desired = $desired; Ids = @('refresh', 'added'); CurrentById = $current
        }

        $ids = @($updated.Desired.nrptRules | ForEach-Object { $_.id })
        $ids | Should-BeCollection @('added', 'keep', 'refresh')
        ($updated.Desired.nrptRules | Where-Object { $_.id -eq 'refresh' }).Namespace |
            Should-BeCollection @('new.example')
    }

}
