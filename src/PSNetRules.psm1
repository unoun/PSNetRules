# PSNetRules manages local Firewall Rules, Profiles, Dynamic Keyword Addresses,
# and DNS Client NRPT state through capture, comparison, and generated change plans.
Set-StrictMode -Version 2.0

$script:NRModulePath = $PSCommandPath

$script:NRFirewallRuleFields = @(
    'DisplayName', 'Description', 'Group', 'Enabled', 'Profile', 'Platform', 'Direction',
    'Action', 'EdgeTraversalPolicy', 'LooseSourceMapping', 'LocalOnlyMapping', 'Owner',
    'RemoteDynamicKeywordAddresses'
)
$script:NRFirewallDynamicKeywordFields = @('Keyword', 'Addresses', 'AutoResolve')
$script:NRFirewallProfileFields = @(
    'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'AllowInboundRules',
    'AllowLocalFirewallRules', 'AllowLocalIPsecRules', 'AllowUserApps', 'AllowUserPorts',
    'AllowUnicastResponseToMulticast', 'NotifyOnListen', 'EnableStealthModeForIPsec',
    'LogFileName', 'LogMaxSizeKilobytes', 'LogAllowed', 'LogBlocked', 'LogIgnored',
    'DisabledInterfaceAliases'
)
$script:NRFirewallFilterFields = [ordered]@{
    address = @('LocalAddress', 'RemoteAddress')
    port = @('Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTarget')
    application = @('Program', 'Package')
    service = @('Service')
    interface = @('InterfaceAlias')
    interfaceType = @('InterfaceType')
    security = @('LocalUser', 'RemoteUser', 'RemoteMachine', 'Authentication', 'Encryption', 'OverrideBlockRules')
}
$script:NRNrptFields = @(
    'Namespace', 'IPsecTrustAuthority', 'DANameServers', 'DAEnable', 'DAIPsecEncryptionType',
    'DAIPsecRequired', 'DAProxyServerName', 'DAProxyType', 'NameServers', 'NameEncoding',
    'DnsSecEnable', 'DnsSecIPsecEncryptionType', 'DnsSecIPsecRequired',
    'DnsSecValidationRequired', 'DisplayName', 'Comment'
)

$script:NRFirewallFilterSpecs = @(
    [pscustomobject]@{ JsonName = 'address'; Cmdlet = 'Get-NetFirewallAddressFilter'; Fields = @('LocalAddress', 'RemoteAddress'); ArrayFields = @('LocalAddress', 'RemoteAddress') },
    [pscustomobject]@{ JsonName = 'port'; Cmdlet = 'Get-NetFirewallPortFilter'; Fields = @('Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTarget'); ArrayFields = @('LocalPort', 'RemotePort', 'IcmpType') },
    [pscustomobject]@{ JsonName = 'application'; Cmdlet = 'Get-NetFirewallApplicationFilter'; Fields = @('Program', 'Package'); ArrayFields = @() },
    [pscustomobject]@{ JsonName = 'service'; Cmdlet = 'Get-NetFirewallServiceFilter'; Fields = @('Service'); ArrayFields = @() },
    [pscustomobject]@{ JsonName = 'interface'; Cmdlet = 'Get-NetFirewallInterfaceFilter'; Fields = @('InterfaceAlias'); ArrayFields = @('InterfaceAlias') },
    [pscustomobject]@{ JsonName = 'interfaceType'; Cmdlet = 'Get-NetFirewallInterfaceTypeFilter'; Fields = @('InterfaceType'); ArrayFields = @() },
    [pscustomobject]@{ JsonName = 'security'; Cmdlet = 'Get-NetFirewallSecurityFilter'; Fields = @('LocalUser', 'RemoteUser', 'RemoteMachine', 'Authentication', 'Encryption', 'OverrideBlockRules'); ArrayFields = @() }
)

function Get-NRProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] [object] $InputObject,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return ,$InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $property) { return ,$property.Value }
    return $null
}

function Test-NRProperty {
    [CmdletBinding()]
    param([object] $InputObject, [string] $Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return ($null -ne $InputObject.PSObject.Properties[$Name])
}

function Test-NRObjectLike {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return $false }
    if ($Value -is [System.Collections.IDictionary]) { return $true }
    if ($Value -is [System.Collections.IEnumerable]) { return $false }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        # JSON objects deserialize as PSCustomObjects; inspect their property
        # collection directly in this frequently evaluated comparison path.
        return (@($Value.PSObject.Properties).Count -gt 0)
    }

    # Adapted PowerShell objects use the general PSObject property path.
    return (@($Value.PSObject.Properties | ForEach-Object { $_.Name }).Count -gt 0)
}

function ConvertTo-NRJsonValue {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Enum]) { return $Value.ToString() }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @($Value.Keys | Sort-Object)) {
            $result[[string]$key] = ConvertTo-NRJsonValue $Value[$key]
        }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @()
        foreach ($item in $Value) { $items += ,(ConvertTo-NRJsonValue $item) }
        return ,$items
    }
    return [string]$Value
}

function Get-NRPropertyNames {
    [CmdletBinding()]
    param([AllowNull()] [object] $InputObject)
    if ($null -eq $InputObject) { return @() }
    if ($InputObject -is [System.Collections.IDictionary]) { return @($InputObject.Keys | ForEach-Object { [string]$_ }) }
    return @($InputObject.PSObject.Properties | ForEach-Object { $_.Name })
}

function Get-NRCanonicalDictionary {
    [CmdletBinding()]
    param([System.Collections.IDictionary] $Value)
    $result = [ordered]@{}
    foreach ($key in @($Value.Keys | Sort-Object)) {
        $result[[string]$key] = Get-NRCanonicalValue $Value[$key]
    }
    return $result
}

function Test-NRCanonicalSequenceContainsObject {
    [CmdletBinding()]
    param([object[]] $Values)
    foreach ($item in $Values) {
        if ((Test-NRObjectLike $item) -or ($item -is [System.Collections.IDictionary]) -or
            ($item -is [System.Collections.IEnumerable] -and $item -isnot [string])) {
            return $true
        }
    }
    return $false
}

function Get-NRCanonicalSequence {
    [CmdletBinding()]
    param([System.Collections.IEnumerable] $Value)
    $items = @()
    foreach ($item in $Value) { $items += ,(Get-NRCanonicalValue $item) }
    if (-not (Test-NRCanonicalSequenceContainsObject -Values $items)) {
        # Keep null elements in the sort input: pipeline enumeration would
        # otherwise discard them before canonicalization.
        $sortableItems = New-Object System.Collections.ArrayList
        foreach ($item in $items) {
            $sortKey = ''
            if ($null -ne $item) { $sortKey = [string]$item }
            $null = $sortableItems.Add([pscustomobject]@{ SortKey = $sortKey; Value = $item })
        }
        $sortedEntries = @($sortableItems | Sort-Object -Property SortKey)
        $sortedItems = New-Object System.Collections.ArrayList
        foreach ($entry in $sortedEntries) { $null = $sortedItems.Add($entry.Value) }
        $items = $sortedItems.ToArray()
    }
    return ,$items
}

function Get-NRCanonicalObject {
    [CmdletBinding()]
    param([object] $Value)
    $result = [ordered]@{}
    foreach ($name in @(Get-NRPropertyNames $Value | Sort-Object)) {
        $result[$name] = Get-NRCanonicalValue (Get-NRProperty $Value $name)
    }
    return $result
}

function Get-NRCanonicalValue {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) { return (Get-NRCanonicalDictionary -Value $Value) }
    if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) { return ,(Get-NRCanonicalSequence -Value $Value) }
    if (Test-NRObjectLike $Value) { return (Get-NRCanonicalObject -Value $Value) }
    return $Value
}

function ConvertTo-NRCanonicalJson {
    [CmdletBinding()]
    param([AllowNull()] [object] $InputObject)
    return (ConvertTo-Json -InputObject (Get-NRCanonicalValue $InputObject) -Depth 100 -Compress)
}

function Get-NRCompactValue {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    if ($null -eq $Value) { return 'null' }
    return (ConvertTo-Json -InputObject (Get-NRCanonicalValue $Value) -Depth 50 -Compress)
}

function Add-NRStringSequenceCounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object] $Value,
        [Parameter(Mandatory = $true)] [System.Collections.Generic.Dictionary[string, int]] $Counts
    )

    $nullCount = 0
    foreach ($item in $Value) {
        if ($null -eq $item) {
            $nullCount++
            continue
        }
        if ($item -isnot [string]) { return $null }
        if ($Counts.ContainsKey($item)) { $Counts[$item]++ }
        else { $Counts.Add($item, 1) }
    }
    return $nullCount
}

function Test-NRStringSequenceCountsEmpty {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [System.Collections.Generic.Dictionary[string, int]] $Counts)

    foreach ($count in $Counts.Values) {
        if ($count -ne 0) { return $false }
    }
    return $true
}

function Test-NRStringSequenceAgainstCounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object] $Value,
        [Parameter(Mandatory = $true)] [System.Collections.Generic.Dictionary[string, int]] $Counts,
        [int] $ExpectedNullCount,
        [bool] $InitialEqual
    )

    $nullCount = 0
    $equal = $InitialEqual
    foreach ($item in $Value) {
        if ($null -eq $item) {
            $nullCount++
            continue
        }
        if ($item -isnot [string]) { return $null }
        if (-not $Counts.ContainsKey($item)) {
            $equal = $false
            continue
        }
        if ($Counts[$item] -eq 0) {
            $equal = $false
            continue
        }
        $Counts[$item]--
    }

    if (-not $equal -or $nullCount -ne $ExpectedNullCount) { return $false }
    return (Test-NRStringSequenceCountsEmpty -Counts $Counts)
}

function Test-NRStringSequenceEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object] $Left,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object] $Right
    )

    # Compare strings as an ordinal, case-sensitive multiset. Return null for
    # non-string sequences so the caller can use the general canonical path.
    $counts = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    $leftNullCount = Add-NRStringSequenceCounts -Value $Left -Counts $counts
    if ($null -eq $leftNullCount) { return $null }
    $leftCount = if ($Left -is [System.Array]) { $Left.Length } else { $Left.Count }
    $rightCount = if ($Right -is [System.Array]) { $Right.Length } else { $Right.Count }
    return (Test-NRStringSequenceAgainstCounts -Value $Right -Counts $counts `
        -ExpectedNullCount $leftNullCount -InitialEqual ($leftCount -eq $rightCount))
}

function Test-NRCanonicalValuesEqual {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Left,
        [AllowNull()] [object] $Right
    )

    if ($null -eq $Left -or $null -eq $Right) {
        return ($null -eq $Left -and $null -eq $Right)
    }
    if ($Left -is [string] -and $Right -is [string]) { return ($Left -ceq $Right) }
    if ($Left -is [bool] -and $Right -is [bool]) { return ($Left -eq $Right) }
    $leftIsSequence = ($Left -is [System.Array] -or $Left -is [System.Collections.ArrayList])
    $rightIsSequence = ($Right -is [System.Array] -or $Right -is [System.Collections.ArrayList])
    if ($leftIsSequence -and $rightIsSequence) {
        $sequenceEqual = Test-NRStringSequenceEqual -Left $Left -Right $Right
        if ($null -ne $sequenceEqual) { return [bool]$sequenceEqual }
    }
    return ((ConvertTo-NRCanonicalJson $Left) -ceq (ConvertTo-NRCanonicalJson $Right))
}

function Get-NRPropertyChange {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Before,
        [AllowNull()] [object] $After,
        [string] $Name,
        [string] $Prefix = ''
    )
    $oldExists = Test-NRProperty $Before $Name
    $newExists = Test-NRProperty $After $Name
    $oldValue = if ($oldExists) { Get-NRProperty $Before $Name } else { $null }
    $newValue = if ($newExists) { Get-NRProperty $After $Name } else { $null }
    $path = if ([string]::IsNullOrEmpty($Prefix)) { $Name } else { "$Prefix.$Name" }

    if ((Test-NRObjectLike $oldValue) -or (Test-NRObjectLike $newValue)) {
        return (Get-NRObjectChanges -Before $oldValue -After $newValue -Prefix $path)
    }
    if (-not (Test-NRCanonicalValuesEqual -Left $oldValue -Right $newValue)) {
        return ('{0}: {1} -> {2}' -f $path, (Get-NRCompactValue $oldValue), (Get-NRCompactValue $newValue))
    }
    return
}

function Get-NRPCustomObjectPropertyNames {
    param(
        [AllowNull()] [object] $Before,
        [AllowNull()] [object] $After
    )

    $nameSet = @{}
    if ($null -ne $Before) {
        foreach ($property in $Before.PSObject.Properties) { $nameSet[$property.Name] = $true }
    }
    if ($null -ne $After) {
        foreach ($property in $After.PSObject.Properties) { $nameSet[$property.Name] = $true }
    }

    # Sort property names with the same current-culture, case-insensitive
    # ordering used by the general object-comparison path.
    $names = [string[]]@($nameSet.Keys)
    [Array]::Sort($names, [System.StringComparer]::CurrentCultureIgnoreCase)
    return $names
}

function Test-NRPropertyValueObjectLike {
    param([AllowNull()] [object] $Value)
    if ($Value -is [System.Collections.IDictionary]) { return $true }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        return (@($Value.PSObject.Properties).Count -gt 0)
    }
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType] -or
        $Value -is [System.Collections.IEnumerable]) { return $false }
    return (Test-NRObjectLike $Value)
}

function Test-NRCustomObjectPropertyValuesEqual {
    param([AllowNull()] [object] $Left, [AllowNull()] [object] $Right)
    if ($null -eq $Left -or $null -eq $Right) {
        return ($null -eq $Left -and $null -eq $Right)
    }
    if ($Left -is [string] -and $Right -is [string]) { return ($Left -ceq $Right) }
    if ($Left -is [bool] -and $Right -is [bool]) { return ($Left -eq $Right) }
    $leftIsSequence = ($Left -is [System.Array] -or $Left -is [System.Collections.ArrayList])
    $rightIsSequence = ($Right -is [System.Array] -or $Right -is [System.Collections.ArrayList])
    if ($leftIsSequence -and $rightIsSequence) {
        $sequenceEqual = Test-NRStringSequenceEqual -Left $Left -Right $Right
        if ($null -ne $sequenceEqual) { return [bool]$sequenceEqual }
    }
    return (Test-NRCanonicalValuesEqual -Left $Left -Right $Right)
}

function Get-NRPCustomObjectPropertyChange {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $BeforeProperty,
        [AllowNull()] [object] $AfterProperty,
        [string] $Name,
        [string] $Prefix = ''
    )
    $oldValue = if ($null -ne $BeforeProperty) { $BeforeProperty.Value } else { $null }
    $newValue = if ($null -ne $AfterProperty) { $AfterProperty.Value } else { $null }
    $path = if ([string]::IsNullOrEmpty($Prefix)) { $Name } else { "$Prefix.$Name" }

    if ((Test-NRPropertyValueObjectLike $oldValue) -or (Test-NRPropertyValueObjectLike $newValue)) {
        return (Get-NRObjectChanges -Before $oldValue -After $newValue -Prefix $path)
    }
    if (-not (Test-NRCustomObjectPropertyValuesEqual -Left $oldValue -Right $newValue)) {
        return ('{0}: {1} -> {2}' -f $path, (Get-NRCompactValue $oldValue), (Get-NRCompactValue $newValue))
    }
    return
}

function Get-NRPCustomObjectChanges {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Before,
        [AllowNull()] [object] $After,
        [string] $Prefix = ''
    )

    $changes = New-Object 'System.Collections.Generic.List[string]'
    $names = Get-NRPCustomObjectPropertyNames -Before $Before -After $After
    foreach ($name in $names) {
        $beforeProperty = if ($null -ne $Before) { $Before.PSObject.Properties[$name] } else { $null }
        $afterProperty = if ($null -ne $After) { $After.PSObject.Properties[$name] } else { $null }
        foreach ($change in @(Get-NRPCustomObjectPropertyChange -BeforeProperty $beforeProperty -AfterProperty $afterProperty -Name $name -Prefix $Prefix)) {
            $changes.Add($change)
        }
    }
    return $changes.ToArray()
}

function Get-NRObjectChanges {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Before,
        [AllowNull()] [object] $After,
        [string] $Prefix = ''
    )
    # JSON-loaded Snapshot and desired-state objects use PSCustomObject
    # properties. Keep that path direct; dictionaries and adapted objects use
    # the general property-access implementation below.
    $beforeIsCustomOrNull = ($null -eq $Before -or $Before -is [System.Management.Automation.PSCustomObject])
    $afterIsCustomOrNull = ($null -eq $After -or $After -is [System.Management.Automation.PSCustomObject])
    if ($beforeIsCustomOrNull -and $afterIsCustomOrNull) {
        return (Get-NRPCustomObjectChanges -Before $Before -After $After -Prefix $Prefix)
    }

    $changes = New-Object System.Collections.Generic.List[string]
    $names = @(@((Get-NRPropertyNames $Before) + (Get-NRPropertyNames $After)) | Select-Object -Unique | Sort-Object)
    foreach ($name in $names) {
        foreach ($change in @(Get-NRPropertyChange -Before $Before -After $After -Name $name -Prefix $Prefix)) {
            $changes.Add($change)
        }
    }
    return $changes.ToArray()
}

function Get-NRMapByKey {
    [CmdletBinding()]
    param([object[]] $Items, [string] $KeyProperty)
    while ($Items.Count -eq 1 -and $Items[0] -is [System.Array]) { $Items = $Items[0] }
    $map = @{}
    foreach ($item in $Items) {
        if ($item -is [System.Management.Automation.PSCustomObject]) {
            $keyMember = $item.PSObject.Properties[$KeyProperty]
            $keyValue = if ($null -ne $keyMember) { $keyMember.Value } else { $null }
        }
        else {
            $keyValue = Get-NRProperty $item $KeyProperty
        }
        $key = [string]$keyValue
        if ([string]::IsNullOrWhiteSpace($key)) { throw "An item has an empty '$KeyProperty'." }
        if ($map.ContainsKey($key)) { throw "Duplicate key '$key' in '$KeyProperty'." }
        $map[$key] = $item
    }
    return $map
}

function Test-NRNullTransition {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Current,
        [AllowNull()] [object] $Desired
    )
    if ($null -eq $Desired) { return ($null -ne $Current) }
    if (Test-NRObjectLike $Desired) {
        foreach ($name in @(Get-NRPropertyNames $Desired)) {
            if (Test-NRNullTransition -Current (Get-NRProperty $Current $name) -Desired (Get-NRProperty $Desired $name)) { return $true }
        }
    }
    return $false
}

function New-NRChangeRecord {
    [CmdletBinding()]
    param([string] $Target, [string] $Key, [string] $Action, [string[]] $Details = @())
    return [pscustomobject]@{ Target = $Target; Key = $Key; Action = $Action; Details = @($Details) }
}

function Get-NRKeyedCollectionDiff {
    [CmdletBinding()]
    param(
        [object[]] $DesiredItems,
        [object[]] $CurrentItems,
        [string] $KeyProperty,
        [string] $Target
    )
    $changes = New-Object System.Collections.Generic.List[object]
    $desiredMap = Get-NRMapByKey -Items $DesiredItems -KeyProperty $KeyProperty
    $currentMap = Get-NRMapByKey -Items $CurrentItems -KeyProperty $KeyProperty

    foreach ($key in @($desiredMap.Keys | Sort-Object)) {
        if (-not $currentMap.ContainsKey($key)) {
            $changes.Add((New-NRChangeRecord -Target $Target -Key $key -Action 'Add'))
            continue
        }
        $details = @(Get-NRObjectChanges -Before $currentMap[$key] -After $desiredMap[$key])
        if ($details.Count -gt 0) {
            $changes.Add((New-NRChangeRecord -Target $Target -Key $key -Action 'Update' -Details $details))
        }
    }
    foreach ($key in @($currentMap.Keys | Where-Object { -not $desiredMap.ContainsKey($_) } | Sort-Object)) {
        $changes.Add((New-NRChangeRecord -Target $Target -Key $key -Action 'Delete'))
    }
    return $changes.ToArray()
}

function Get-NRProfileDiff {
    [CmdletBinding()]
    param([object] $DesiredProfiles, [object] $CurrentProfiles)
    $changes = New-Object System.Collections.Generic.List[object]
    foreach ($profileName in @('Domain', 'Private', 'Public')) {
        $desiredProfileRecord = Get-NRProperty $DesiredProfiles $profileName
        $currentProfileRecord = Get-NRProperty $CurrentProfiles $profileName
        $details = @(Get-NRObjectChanges -Before $currentProfileRecord -After $desiredProfileRecord)
        if ($details.Count -gt 0) {
            $changes.Add((New-NRChangeRecord -Target 'FirewallProfile' -Key $profileName -Action 'Update' -Details $details))
        }
    }
    return $changes.ToArray()
}

function Get-NRDiff {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Desired,
        [Parameter(Mandatory = $true)] [object] $Current,
        [switch] $SkipFirewallRules
    )
    $changes = New-Object System.Collections.Generic.List[object]
    $collections = New-Object 'System.Collections.Generic.List[object]'
    $collections.Add(@{ Desired = 'firewallDynamicKeywordAddresses'; Current = 'firewallDynamicKeywordAddresses'; Key = 'id'; Target = 'FirewallDynamicKeywordAddress' })
    if (-not $SkipFirewallRules) {
        $collections.Add(@{ Desired = 'firewallRules'; Current = 'firewallRules'; Key = 'name'; Target = 'FirewallRule' })
    }
    $collections.Add(@{ Desired = 'nrptRules'; Current = 'nrptRules'; Key = 'id'; Target = 'NrptRule' })
    foreach ($collection in $collections) {
        $diffItems = Get-NRKeyedCollectionDiff `
            -DesiredItems (Get-NRProperty $Desired $collection.Desired) `
            -CurrentItems (Get-NRProperty $Current $collection.Current) `
            -KeyProperty $collection.Key -Target $collection.Target
        foreach ($item in $diffItems) { $changes.Add($item) }
    }
    $profileDiff = Get-NRProfileDiff `
        -DesiredProfiles (Get-NRProperty $Desired 'firewallProfiles') `
        -CurrentProfiles (Get-NRProperty $Current 'firewallProfiles')
    foreach ($item in $profileDiff) { $changes.Add($item) }
    return $changes.ToArray()
}

function Format-NRDiff {
    [CmdletBinding()]
    param([object[]] $Changes)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    if (@($Changes).Count -eq 0) {
        $lines.Add('No changes.')
        return $lines.ToArray()
    }
    foreach ($change in @($Changes)) {
        $prefix = switch ($change.Action) { 'Add' { '+' } 'Update' { '~' } 'Delete' { '-' } default { '?' } }
        $lines.Add(('{0} {1}: {2} ({3})' -f $prefix, $change.Target, $change.Key, $change.Action))
        foreach ($detail in @($change.Details)) { $lines.Add(('    {0}' -f $detail)) }
    }
    return $lines.ToArray()
}

function Resolve-NRFilePath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [string] $Path)

    $provider = $null
    $drive = $null
    try {
        # PowerShell maintains a provider location that can differ from
        # Environment.CurrentDirectory (for example after Set-Location or
        # when launched through an elevated host). Resolve relative paths
        # against the PowerShell location, not the process working directory.
        $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
            $Path, [ref]$provider, [ref]$drive
        )
    }
    catch {
        throw "Unable to resolve path '$Path' from the PowerShell current location: $($_.Exception.Message)"
    }

    if ($null -ne $provider -and $provider.Name -ne 'FileSystem') {
        throw "Only FileSystem paths are supported: $Path"
    }

    return [System.IO.Path]::GetFullPath($providerPath)
}

function Get-NRStatePath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Path)
    $full = Resolve-NRFilePath -Path $Path
    $directory = [System.IO.Path]::GetDirectoryName($full)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($full)
    return [System.IO.Path]::Combine($directory, ($baseName + '.state.json'))
}

function Get-NRSnapshotPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Path)
    $full = Resolve-NRFilePath -Path $Path
    $directory = [System.IO.Path]::GetDirectoryName($full)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($full)
    return [System.IO.Path]::Combine($directory, ($baseName + '.snapshot.json'))
}

function Read-NRSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Capture snapshot not found: $Path. Run capture first."
    }
    try {
        # Read the Snapshot as one UTF-8 string. This avoids the PowerShell
        # provider pipeline for a potentially large sidecar file.
        $snapshotJson = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        $snapshot = ConvertFrom-Json -InputObject $snapshotJson -ErrorAction Stop
    }
    catch { throw "Unable to parse snapshot file '$Path': $($_.Exception.Message)" }
    if ((Get-NRProperty $snapshot 'schemaVersion') -ne 1 -or
        $null -eq (Get-NRProperty $snapshot 'configuration') -or
        $null -eq (Get-NRProperty $snapshot 'comparison')) {
        throw "Invalid capture snapshot '$Path'."
    }
    return $snapshot
}

function Add-NRManagedFirewallRuleName {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Entry,
        [hashtable] $Seen,
        [System.Collections.Generic.List[string]] $Names,
        [switch] $RejectDuplicates
    )
    if ($Entry -isnot [string]) { throw 'Managed Firewall rule Name entries must be scalar strings.' }
    $name = $Entry
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'Managed Firewall rule Name cannot be empty.' }
    if ($Seen.ContainsKey($name)) {
        if ($RejectDuplicates) { throw "Duplicate managed Firewall rule Name '$name'." }
        return
    }
    $Seen[$name] = $true
    $Names.Add($name)
}

function Get-NRManagedFirewallRuleNames {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value, [switch] $RejectDuplicates)
    if ($Value -isnot [System.Array] -and $Value -isnot [System.Collections.ArrayList]) {
        throw 'Managed Firewall rule inventory must be an array of strings.'
    }
    $names = New-Object 'System.Collections.Generic.List[string]'
    $seen = @{}
    foreach ($entry in $Value) {
        Add-NRManagedFirewallRuleName -Entry $entry -Seen $seen -Names $names -RejectDuplicates:$RejectDuplicates
    }
    return $names.ToArray()
}

function Read-NRStateFile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ schemaVersion = 1; nrptRules = @{}; managedFirewallRules = @() }
    }
    try { $state = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Unable to parse state file '$Path': $($_.Exception.Message)" }
    $stored = Get-NRProperty $state 'nrptRules'
    $storedManaged = Get-NRProperty $state 'managedFirewallRules'
    if ((Get-NRProperty $state 'schemaVersion') -ne 1 -or
        -not (Test-NRProperty $state 'nrptRules') -or
        ($stored -isnot [System.Collections.IDictionary] -and $stored -isnot [System.Management.Automation.PSCustomObject]) -or
        -not (Test-NRProperty $state 'managedFirewallRules') -or $null -eq $storedManaged) {
        throw "Invalid state file '$Path'. Expected schemaVersion 1 with an nrptRules object and a managedFirewallRules array."
    }
    $map = @{}
    $reverse = @{}
    foreach ($id in @(Get-NRPropertyNames $stored)) {
        $name = Get-NRProperty $stored $id
        if ([string]::IsNullOrWhiteSpace($id) -or $name -isnot [string] -or [string]::IsNullOrWhiteSpace($name)) {
            throw "Invalid NRPT state mapping in '$Path'."
        }
        if ($reverse.ContainsKey($name)) { throw "Windows NRPT Name '$name' is mapped by multiple logical ids in '$Path'." }
        $map[$id] = $name
        $reverse[$name] = $id
    }
    try { $managed = @(Get-NRManagedFirewallRuleNames -Value $storedManaged -RejectDuplicates) }
    catch { throw "Invalid managed Firewall rule inventory in '$Path': $($_.Exception.Message)" }
    return [pscustomobject]@{ schemaVersion = 1; nrptRules = $map; managedFirewallRules = $managed }
}

# Write JSON as BOM-less UTF-8; sidecar readers specify UTF-8 explicitly.
function Write-NRJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [object] $InputObject,
        [switch] $Compress
    )
    $full = Resolve-NRFilePath -Path $Path
    $directory = [System.IO.Path]::GetDirectoryName($full)
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
    }
    $json = ConvertTo-Json -InputObject $InputObject -Depth 100 -Compress:$Compress
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($full, ($json + [Environment]::NewLine), $encoding)
}

function Write-NRStateFile {
    [CmdletBinding()]
    param([string] $Path, [object] $State)
    $plain = [ordered]@{ schemaVersion = 1; nrptRules = [ordered]@{}; managedFirewallRules = @() }
    $nrptRules = Get-NRProperty $State 'nrptRules'
    foreach ($id in @($nrptRules.Keys | Sort-Object)) { $plain.nrptRules[$id] = $nrptRules[$id] }
    $managedValues = Get-NRProperty $State 'managedFirewallRules'
    $managedNames = @(Get-NRManagedFirewallRuleNames -Value $managedValues)
    $plain.managedFirewallRules = @($managedNames | Sort-Object)
    Write-NRJsonFile -Path $Path -InputObject $plain
}

function Read-NRConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Path)
    $Path = Resolve-NRFilePath -Path $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Configuration file not found: $Path" }
    try { return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw "Unable to parse JSON '$Path': $($_.Exception.Message)" }
}

function Assert-NRRequiredObjectFields {
    param([object] $Object, [string[]] $RequiredFields, [string] $Context)
    foreach ($field in $RequiredFields) {
        if (-not (Test-NRProperty $Object $field)) { throw "$Context.$field is required." }
    }
}

function Assert-NRAllowedObjectFields {
    param([object] $Object, [string[]] $AllowedFields, [string] $Context)
    foreach ($field in @(Get-NRPropertyNames $Object)) {
        if ($field -notin $AllowedFields) { throw "$Context contains unsupported property '$field'." }
    }
}

function Assert-NRObjectShape {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Object,
        [Parameter(Mandatory = $true)] [string[]] $RequiredFields,
        [Parameter(Mandatory = $true)] [string[]] $AllowedFields,
        [Parameter(Mandatory = $true)] [string] $Context
    )
    if ($null -eq $Object) { throw "$Context is required and must be an object." }

    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        foreach ($field in $RequiredFields) {
            if ($null -eq $Object.PSObject.Properties[$field]) { throw "$Context.$field is required." }
        }
        foreach ($property in $Object.PSObject.Properties) {
            if ($AllowedFields -notcontains $property.Name) {
                throw "$Context contains unsupported property '$($property.Name)'."
            }
        }
        return
    }

    Assert-NRRequiredObjectFields -Object $Object -RequiredFields $RequiredFields -Context $Context
    Assert-NRAllowedObjectFields -Object $Object -AllowedFields $AllowedFields -Context $Context
}

function Test-NRNumberValue {
    [CmdletBinding()]
    param([object] $Value)
    return ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or
        $Value -is [int64] -or $Value -is [single] -or $Value -is [double] -or
        $Value -is [decimal] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64])
}

function Test-NRScalarValue {
    [CmdletBinding()]
    param([object] $Value)
    return ($Value -is [string] -or $Value -is [bool] -or $Value -is [System.Enum] -or (Test-NRNumberValue $Value))
}

function Test-NRStringArrayValue {
    [CmdletBinding()]
    param([object] $Value)
    if ($Value -isnot [System.Collections.IEnumerable] -or $Value -is [string]) { return $false }
    foreach ($item in $Value) { if ($item -isnot [string]) { return $false } }
    return $true
}

function Test-NRStringOrArrayValue {
    [CmdletBinding()]
    param([object] $Value)
    return ($Value -is [string] -or (Test-NRStringArrayValue $Value))
}

function Test-NRFieldValue {
    [CmdletBinding()]
    param([object] $Value, [string] $Kind)
    switch ($Kind) {
        'string' { return ($Value -is [string]) }
        'boolean' { return ($Value -is [bool]) }
        'number' { return (Test-NRNumberValue $Value) }
        'scalar' { return (Test-NRScalarValue $Value) }
        'stringArray' { return (Test-NRStringArrayValue $Value) }
        'stringOrArray' { return (Test-NRStringOrArrayValue $Value) }
    }
    return $false
}

function Get-NRFieldValueForValidation {
    param([AllowNull()] [object] $Object, [string] $Field)
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        $property = $Object.PSObject.Properties[$Field]
        if ($null -eq $property) { return }
        return ,$property.Value
    }
    if ($Object -is [System.Collections.IDictionary]) {
        if (-not $Object.Contains($Field)) { return }
        return ,$Object[$Field]
    }
    return ,(Get-NRProperty $Object $Field)
}

function Assert-NRFieldType {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Object,
        [Parameter(Mandatory = $true)] [string] $Field,
        [Parameter(Mandatory = $true)] [ValidateSet('string', 'boolean', 'number', 'stringArray', 'stringOrArray', 'scalar')] [string] $Kind,
        [Parameter(Mandatory = $true)] [string] $Context
    )

    $value = Get-NRFieldValueForValidation -Object $Object -Field $Field
    if ($null -eq $value) { return }
    if (-not (Test-NRFieldValue -Value $value -Kind $Kind)) {
        throw "$Context.$Field must be $Kind or null."
    }
}

function Assert-NRArrayField {
    [CmdletBinding()]
    param([object] $Object, [string] $Field)
    $value = Get-NRProperty $Object $Field
    if ($null -eq $value -or $value -is [string] -or $value -isnot [System.Collections.IEnumerable]) {
        throw "$Field must be an array."
    }
}

function Assert-NRFirewallProfile {
    [CmdletBinding()]
    param([object] $ProfileRecord, [string] $ProfileName)
    $context = "firewallProfiles.$ProfileName"
    Assert-NRObjectShape -Object $ProfileRecord -RequiredFields $script:NRFirewallProfileFields `
        -AllowedFields $script:NRFirewallProfileFields -Context $context
    $scalarFields = @('Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'AllowInboundRules',
        'AllowLocalFirewallRules', 'AllowLocalIPsecRules', 'AllowUserApps', 'AllowUserPorts',
        'AllowUnicastResponseToMulticast', 'NotifyOnListen', 'EnableStealthModeForIPsec',
        'LogAllowed', 'LogBlocked', 'LogIgnored')
    foreach ($field in $scalarFields) { Assert-NRFieldType -Object $ProfileRecord -Field $field -Kind scalar -Context $context }
    Assert-NRFieldType -Object $ProfileRecord -Field 'LogFileName' -Kind string -Context $context
    Assert-NRFieldType -Object $ProfileRecord -Field 'LogMaxSizeKilobytes' -Kind number -Context $context
    Assert-NRFieldType -Object $ProfileRecord -Field 'DisabledInterfaceAliases' -Kind stringArray -Context $context
}

function Assert-NRFirewallProfiles {
    [CmdletBinding()]
    param([object] $Profiles)
    $names = @('Domain', 'Private', 'Public')
    Assert-NRObjectShape -Object $Profiles -RequiredFields $names -AllowedFields $names -Context 'firewallProfiles'
    foreach ($profileName in $names) {
        Assert-NRFirewallProfile -ProfileRecord (Get-NRProperty $Profiles $profileName) -ProfileName $profileName
    }
}

function Assert-NRDynamicKeywordAddress {
    [CmdletBinding()]
    param([object] $Address, [hashtable] $KnownIds)
    $fields = @('id') + $script:NRFirewallDynamicKeywordFields
    Assert-NRObjectShape -Object $Address -RequiredFields $fields -AllowedFields $fields -Context 'firewallDynamicKeywordAddresses[]'
    $dynamicId = [string](Get-NRProperty $Address 'id')
    if ($dynamicId -notmatch '^\{[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}$') {
        throw "Dynamic keyword address id '$dynamicId' must be a GUID enclosed in braces."
    }
    if ($KnownIds.ContainsKey($dynamicId)) { throw "Duplicate dynamic keyword address id '$dynamicId'." }
    Assert-NRFieldType $Address 'Keyword' string 'firewallDynamicKeywordAddresses[]'
    Assert-NRFieldType $Address 'Addresses' string 'firewallDynamicKeywordAddresses[]'
    Assert-NRFieldType $Address 'AutoResolve' boolean 'firewallDynamicKeywordAddresses[]'
    if ($null -eq (Get-NRProperty $Address 'AutoResolve')) { throw "Dynamic keyword address '$dynamicId' must declare AutoResolve." }
    if ([string]::IsNullOrWhiteSpace([string](Get-NRProperty $Address 'Keyword'))) { throw "Dynamic keyword address '$dynamicId' must have a Keyword." }
    $autoResolve = [bool](Get-NRProperty $Address 'AutoResolve')
    $addresses = Get-NRProperty $Address 'Addresses'
    if ($autoResolve -and $null -ne $addresses) { throw "AutoResolve dynamic keyword address '$dynamicId' must not declare Addresses." }
    if (-not $autoResolve -and [string]::IsNullOrWhiteSpace([string]$addresses)) {
        throw "Non-AutoResolve dynamic keyword address '$dynamicId' must declare Addresses."
    }
    $KnownIds[$dynamicId] = $true
}

function Assert-NRFirewallDynamicKeywordAddresses {
    [CmdletBinding()]
    param([object[]] $Addresses)
    $knownIds = @{}
    foreach ($address in $Addresses) { Assert-NRDynamicKeywordAddress -Address $address -KnownIds $knownIds }
    return $knownIds
}

function Assert-NRFirewallRuleBody {
    [CmdletBinding()]
    param([object] $RuleBody, [string] $Name)
    $fields = @('name') + $script:NRFirewallRuleFields
    $context = "firewallRules[$Name].rule"
    Assert-NRObjectShape -Object $RuleBody -RequiredFields $fields -AllowedFields $fields -Context $context
    $innerName = [string](Get-NRProperty $RuleBody 'name')
    if ($innerName -cne $Name) { throw "Firewall rule '$Name' has mismatched rule.name '$innerName'." }
    foreach ($field in @('DisplayName', 'Description', 'Group', 'Owner')) {
        Assert-NRFieldType -Object $RuleBody -Field $field -Kind string -Context $context
    }
    foreach ($field in @('Enabled', 'Direction', 'Action', 'EdgeTraversalPolicy')) {
        Assert-NRFieldType -Object $RuleBody -Field $field -Kind scalar -Context $context
    }
    foreach ($field in @('LooseSourceMapping', 'LocalOnlyMapping')) {
        Assert-NRFieldType -Object $RuleBody -Field $field -Kind boolean -Context $context
    }
    Assert-NRFieldType -Object $RuleBody -Field 'Profile' -Kind stringOrArray -Context $context
    Assert-NRFieldType -Object $RuleBody -Field 'Platform' -Kind stringArray -Context $context
    Assert-NRFieldType -Object $RuleBody -Field 'RemoteDynamicKeywordAddresses' -Kind stringArray -Context $context
}

function Assert-NRFirewallFilter {
    [CmdletBinding()]
    param([object] $Filter, [string] $FilterName, [string] $Context)
    $fields = $script:NRFirewallFilterFields[$FilterName]
    Assert-NRObjectShape -Object $Filter -RequiredFields $fields -AllowedFields $fields -Context $Context
    switch ($FilterName) {
        'address' {
            Assert-NRFieldType $Filter 'LocalAddress' stringArray $Context
            Assert-NRFieldType $Filter 'RemoteAddress' stringArray $Context
        }
        'port' {
            Assert-NRFieldType $Filter 'Protocol' string $Context
            foreach ($field in @('LocalPort', 'RemotePort', 'IcmpType')) { Assert-NRFieldType $Filter $field stringArray $Context }
            Assert-NRFieldType $Filter 'DynamicTarget' string $Context
        }
        'application' {
            Assert-NRFieldType $Filter 'Program' string $Context
            Assert-NRFieldType $Filter 'Package' string $Context
        }
        'service' { Assert-NRFieldType $Filter 'Service' string $Context }
        'interface' { Assert-NRFieldType $Filter 'InterfaceAlias' stringArray $Context }
        'interfaceType' { Assert-NRFieldType $Filter 'InterfaceType' stringOrArray $Context }
        'security' {
            foreach ($field in @('LocalUser', 'RemoteUser', 'RemoteMachine', 'Authentication', 'Encryption')) {
                Assert-NRFieldType $Filter $field string $Context
            }
            Assert-NRFieldType $Filter 'OverrideBlockRules' boolean $Context
        }
    }
}

function Assert-NRFirewallRule {
    [CmdletBinding()]
    param([object] $Rule, [hashtable] $Names, [hashtable] $DynamicIds)
    $outerFields = @('name', 'rule', 'filters')
    Assert-NRObjectShape -Object $Rule -RequiredFields $outerFields -AllowedFields $outerFields -Context 'firewallRules[]'
    $name = [string](Get-NRProperty $Rule 'name')
    if ([string]::IsNullOrWhiteSpace($name)) { throw 'Every firewall rule must have a non-empty name.' }
    if ($Names.ContainsKey($name)) { throw "Duplicate firewall rule name '$name'." }
    $Names[$name] = $true

    $ruleBody = Get-NRProperty $Rule 'rule'
    Assert-NRFirewallRuleBody -RuleBody $ruleBody -Name $name
    $references = Get-NRProperty $ruleBody 'RemoteDynamicKeywordAddresses'
    foreach ($dynamicId in $references) {
        if (-not $DynamicIds.ContainsKey([string]$dynamicId)) {
            throw "Firewall rule '$name' references undeclared dynamic keyword address '$dynamicId'."
        }
    }

    $filters = Get-NRProperty $Rule 'filters'
    $filterNames = @($script:NRFirewallFilterFields.Keys)
    Assert-NRObjectShape -Object $filters -RequiredFields $filterNames -AllowedFields $filterNames -Context "firewallRules[$name].filters"
    foreach ($filterName in $filterNames) {
        $filterContext = "firewallRules[$name].filters.$filterName"
        Assert-NRFirewallFilter -Filter (Get-NRProperty $filters $filterName) -FilterName $filterName -Context $filterContext
    }
}

function Assert-NRFirewallRules {
    [CmdletBinding()]
    param([object[]] $Rules, [hashtable] $DynamicIds)
    $names = @{}
    foreach ($rule in $Rules) { Assert-NRFirewallRule -Rule $rule -Names $names -DynamicIds $DynamicIds }
}

function Assert-NRNrptRule {
    [CmdletBinding()]
    param([object] $Rule, [hashtable] $Ids)
    $fields = @('id') + $script:NRNrptFields
    Assert-NRObjectShape -Object $Rule -RequiredFields $fields -AllowedFields $fields -Context 'nrptRules[]'
    $id = [string](Get-NRProperty $Rule 'id')
    if ([string]::IsNullOrWhiteSpace($id)) { throw 'Every NRPT rule must have a non-empty id.' }
    if ($Ids.ContainsKey($id)) { throw "Duplicate NRPT id '$id'." }
    $Ids[$id] = $true

    $namespaces = @(Get-NRProperty $Rule 'Namespace')
    if ($namespaces.Count -eq 0 -or @($namespaces | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
        throw "NRPT rule '$id' must contain at least one non-empty Namespace."
    }
    foreach ($field in @('Namespace', 'DANameServers', 'NameServers')) { Assert-NRFieldType $Rule $field stringArray "nrptRules[$id]" }
    foreach ($field in @('DAEnable', 'DAIPsecRequired', 'DnsSecEnable', 'DnsSecIPsecRequired', 'DnsSecValidationRequired')) {
        Assert-NRFieldType $Rule $field boolean "nrptRules[$id]"
    }
    foreach ($field in @('IPsecTrustAuthority', 'DAIPsecEncryptionType', 'DAProxyServerName', 'DAProxyType',
        'NameEncoding', 'DnsSecIPsecEncryptionType', 'DisplayName', 'Comment')) {
        Assert-NRFieldType $Rule $field string "nrptRules[$id]"
    }
}

function Assert-NRNrptRules {
    [CmdletBinding()]
    param([object[]] $Rules)
    $ids = @{}
    foreach ($rule in $Rules) { Assert-NRNrptRule -Rule $rule -Ids $ids }
}

function Get-NRExcludedFirewallRuleNames {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Configuration)
    $value = Get-NRProperty $Configuration 'excludedFirewallRules'
    if ($null -eq $value) { return @() }
    $names = ConvertTo-NRObjectArray -Value $value
    if ($null -eq $names) { return @() }
    return @($names)
}

function Set-NRExcludedFirewallRuleNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Configuration,
        [string[]] $Names = @()
    )
    $values = @($Names | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
    if ($Configuration -is [System.Collections.IDictionary]) {
        $Configuration['excludedFirewallRules'] = $values
    }
    elseif (Test-NRProperty -InputObject $Configuration -Name 'excludedFirewallRules') {
        $Configuration.excludedFirewallRules = $values
    }
    else {
        Add-Member -InputObject $Configuration -MemberType NoteProperty -Name 'excludedFirewallRules' -Value $values
    }
    return $Configuration
}

function Assert-NRExcludedFirewallRules {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Configuration)

    if (-not (Test-NRProperty $Configuration 'excludedFirewallRules')) { return }
    Assert-NRArrayField -Object $Configuration -Field 'excludedFirewallRules'

    $managedNames = @{}
    foreach ($record in $Configuration.firewallRules) {
        $managedNames[[string](Get-NRProperty $record 'name')] = $true
    }

    $excludedNames = @{}
    foreach ($name in @(Get-NRExcludedFirewallRuleNames -Configuration $Configuration)) {
        if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name)) {
            throw 'excludedFirewallRules must contain non-empty strings.'
        }
        if ($excludedNames.ContainsKey($name)) {
            throw "Duplicate excluded Firewall rule name '$name'."
        }
        if ($managedNames.ContainsKey($name)) {
            throw "Firewall rule '$name' cannot be both managed and excluded."
        }
        $excludedNames[$name] = $true
    }
}


function Assert-NRConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Configuration)

    $rootFields = @('schemaVersion', 'firewallProfiles', 'firewallDynamicKeywordAddresses', 'firewallRules', 'nrptRules', 'excludedFirewallRules')
    Assert-NRObjectShape -Object $Configuration -RequiredFields @('schemaVersion', 'firewallProfiles', 'firewallDynamicKeywordAddresses', 'firewallRules', 'nrptRules') -AllowedFields $rootFields -Context 'configuration'
    if ((Get-NRProperty $Configuration 'schemaVersion') -ne 1) { throw 'schemaVersion must be 1.' }

    Assert-NRFirewallProfiles -Profiles (Get-NRProperty $Configuration 'firewallProfiles')
    foreach ($field in @('firewallDynamicKeywordAddresses', 'firewallRules', 'nrptRules')) {
        Assert-NRArrayField -Object $Configuration -Field $field
    }

    $dynamicIds = Assert-NRFirewallDynamicKeywordAddresses -Addresses (Get-NRProperty $Configuration 'firewallDynamicKeywordAddresses')
    Assert-NRFirewallRules -Rules (Get-NRProperty $Configuration 'firewallRules') -DynamicIds $dynamicIds
    Assert-NRExcludedFirewallRules -Configuration $Configuration
    Assert-NRNrptRules -Rules (Get-NRProperty $Configuration 'nrptRules')
    return $true
}

function Test-NRIsAdministrator {
    [CmdletBinding()]
    param()
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NRAdministrator {
    [CmdletBinding()]
    param()
    if ($env:OS -ne 'Windows_NT') { throw 'This command requires Windows.' }
    if (-not (Test-NRIsAdministrator)) {
        throw 'Administrator privileges are required. Run this command through Windows sudo.'
    }
}

function Get-NRValueFromObject {
    [CmdletBinding()]
    param([object] $Object, [string] $Name)
    return ConvertTo-NRJsonValue (Get-NRProperty $Object $Name)
}

function Get-NRStringArrayFromObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Object,
        [Parameter(Mandatory = $true)] [string] $Name
    )
    $value = Get-NRProperty -InputObject $Object -Name $Name
    if ($null -eq $value) { return $null }

    $items = New-Object 'System.Collections.Generic.List[string]'
    if ($value -is [string] -or $value -is [ValueType] -or $value -is [System.Enum]) {
        $items.Add([string]$value)
    }
    elseif ($value -is [System.Collections.IEnumerable]) {
        foreach ($item in $value) {
            if ($null -ne $item) { $items.Add([string](ConvertTo-NRJsonValue $item)) }
        }
    }
    else {
        $items.Add([string]$value)
    }
    return ,([string[]]$items.ToArray())
}

function Get-NRFirewallFilterSpecs {
    [CmdletBinding()]
    param()
    return $script:NRFirewallFilterSpecs
}

function ConvertTo-NRFirewallFilterRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $FilterItem,
        [Parameter(Mandatory = $true)] [object] $Spec
    )

    $filterRecord = [ordered]@{}
    foreach ($field in $Spec.Fields) {
        $value = if ($Spec.ArrayFields -contains $field) {
            Get-NRStringArrayFromObject -Object $FilterItem -Name $field
        }
        else {
            Get-NRValueFromObject -Object $FilterItem -Name $field
        }
        $filterRecord[$field] = $value
    }
    return [pscustomobject]$filterRecord
}

function Add-NRFirewallFilterToIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $FilterItem,
        [Parameter(Mandatory = $true)] [object] $Spec,
        [Parameter(Mandatory = $true)] [hashtable] $Index,
        [Parameter(Mandatory = $true)] [hashtable] $RequestedRuleNames,
        [switch] $FilterToRequestedRules,
        [AllowNull()] [hashtable] $NativeIndex
    )

    $instanceId = [string](Get-NRProperty -InputObject $FilterItem -Name 'InstanceID')
    if ([string]::IsNullOrWhiteSpace($instanceId)) {
        if ($FilterToRequestedRules) { return }
        throw "$($Spec.Cmdlet) returned a filter without InstanceID. Cannot associate it with a Firewall rule."
    }
    if ($FilterToRequestedRules -and -not $RequestedRuleNames.ContainsKey($instanceId)) { return }
    if ($Index.ContainsKey($instanceId)) {
        throw "$($Spec.Cmdlet) returned duplicate filter InstanceID '$instanceId'."
    }

    $Index[$instanceId] = ConvertTo-NRFirewallFilterRecord -FilterItem $FilterItem -Spec $Spec
    if ($null -ne $NativeIndex) { $NativeIndex[$instanceId] = $FilterItem }
}

function Get-NRFirewallFilterCollectionIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Spec,
        [Parameter(Mandatory = $true)] [hashtable] $RequestedRuleNames,
        [string] $PolicyStore = 'PersistentStore',
        [switch] $FilterToRequestedRules,
        [switch] $IncludeNativeObjects
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $items = @(& $Spec.Cmdlet -All -PolicyStore $PolicyStore -ErrorAction Stop)
    $collectionIndex = @{}
    $nativeIndex = if ($IncludeNativeObjects) { @{} } else { $null }
    foreach ($item in $items) {
        Add-NRFirewallFilterToIndex -FilterItem $item -Spec $Spec -Index $collectionIndex `
            -RequestedRuleNames $RequestedRuleNames -FilterToRequestedRules:$FilterToRequestedRules -NativeIndex $nativeIndex
    }
    $timer.Stop()

    return [pscustomobject]@{
        Index = $collectionIndex
        NativeIndex = $nativeIndex
        Count = $collectionIndex.Count
        ElapsedSeconds = $timer.Elapsed.TotalSeconds
    }
}

function Write-NRFirewallFilterProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Spec,
        [Parameter(Mandatory = $true)] [int] $Index,
        [Parameter(Mandatory = $true)] [int] $Total,
        [AllowNull()] [object] $Result
    )

    if ($null -eq $Result) {
        $percent = [int](($Index / $Total) * 100)
        Write-Progress -Id 2 -ParentId 1 -Activity 'Loading Firewall filters' `
            -Status ("Reading {0} ({1}/{2})" -f $Spec.JsonName, ($Index + 1), $Total) `
            -PercentComplete $percent
        return
    }

    $percent = [int]((($Index + 1) / $Total) * 100)
    Write-Progress -Id 2 -ParentId 1 -Activity 'Loading Firewall filters' `
        -Status ("Loaded {0}: {1} filter objects ({2:N1}s)" -f $Spec.JsonName, $Result.Count, $Result.ElapsedSeconds) `
        -PercentComplete $percent
}

function Get-NRFirewallFilterIndex {
    [CmdletBinding()]
    param(
        [switch] $ShowProgress,
        [string[]] $RuleNames,
        [string] $PolicyStore = 'PersistentStore',
        [switch] $IncludeNativeObjects
    )

    $requestedNames = @{}
    $filterToRequestedRules = $PSBoundParameters.ContainsKey('RuleNames')
    foreach ($name in @($RuleNames)) {
        if (-not [string]::IsNullOrWhiteSpace($name)) { $requestedNames[[string]$name] = $true }
    }

    $specs = @(Get-NRFirewallFilterSpecs)
    $index = @{}
    $nativeIndexes = @{}
    for ($specIndex = 0; $specIndex -lt $specs.Count; $specIndex++) {
        $spec = $specs[$specIndex]
        if ($ShowProgress) { Write-NRFirewallFilterProgress -Spec $spec -Index $specIndex -Total $specs.Count -Result $null }

        if ($IncludeNativeObjects) {
            $result = Get-NRFirewallFilterCollectionIndex -Spec $spec -RequestedRuleNames $requestedNames `
                -PolicyStore $PolicyStore -FilterToRequestedRules:$filterToRequestedRules -IncludeNativeObjects
        }
        else {
            $result = Get-NRFirewallFilterCollectionIndex -Spec $spec -RequestedRuleNames $requestedNames `
                -PolicyStore $PolicyStore -FilterToRequestedRules:$filterToRequestedRules
        }
        $index[$spec.JsonName] = $result.Index
        if ($IncludeNativeObjects) { $nativeIndexes[$spec.JsonName] = $result.NativeIndex }
        if ($ShowProgress) { Write-NRFirewallFilterProgress -Spec $spec -Index $specIndex -Total $specs.Count -Result $result }
    }

    if ($ShowProgress) { Write-Progress -Id 2 -ParentId 1 -Activity 'Loading Firewall filters' -Completed }
    if ($IncludeNativeObjects) {
        return [pscustomobject]@{ RecordIndex = $index; NativeIndexes = $nativeIndexes }
    }
    return $index
}

function Get-NRFirewallFilterFromIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Rule,
        [Parameter(Mandatory = $true)] [hashtable] $FilterIndex
    )
    $ruleName = [string](Get-NRProperty -InputObject $Rule -Name 'Name')
    if ([string]::IsNullOrWhiteSpace($ruleName)) { throw 'Cannot associate Firewall filters with a rule whose Name is empty.' }

    $filters = [ordered]@{}
    foreach ($spec in @(Get-NRFirewallFilterSpecs)) {
        if (-not $FilterIndex.ContainsKey($spec.JsonName)) {
            throw "Firewall filter index is missing '$($spec.JsonName)'."
        }
        $byInstanceId = $FilterIndex[$spec.JsonName]
        if (-not $byInstanceId.ContainsKey($ruleName)) {
            throw "No $($spec.JsonName) filter was returned for firewall rule '$ruleName'."
        }
        $filters[$spec.JsonName] = $byInstanceId[$ruleName]
    }
    return $filters
}

function Get-NRFirewallFilter {
    [CmdletBinding()]
    param([object] $Rule)
    # Resolve filters for one Rule. Capture uses a shared index for the full
    # Rule collection; this helper remains useful for single-Rule callers.
    $ruleName = [string](Get-NRProperty -InputObject $Rule -Name 'Name')
    $filterIndex = Get-NRFirewallFilterIndex -RuleNames @($ruleName)
    return Get-NRFirewallFilterFromIndex -Rule $Rule -FilterIndex $filterIndex
}

function Get-NRFirewallRuleNames {
    [CmdletBinding()]
    param([object[]] $Rules)

    $names = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rule in $Rules) {
        $name = [string](Get-NRProperty -InputObject $rule -Name 'Name')
        if ([string]::IsNullOrWhiteSpace($name)) { throw 'A PersistentStore firewall rule has an empty Name.' }
        $names.Add($name)
    }
    return $names.ToArray()
}

function ConvertTo-NRFirewallRuleRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Rule,
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [hashtable] $FilterIndex
    )

    $body = [ordered]@{ name = $Name }
    foreach ($field in $script:NRFirewallRuleFields) {
        $body[$field] = if ($field -in @('Platform', 'RemoteDynamicKeywordAddresses')) {
            Get-NRStringArrayFromObject -Object $Rule -Name $field
        }
        else {
            Get-NRValueFromObject -Object $Rule -Name $field
        }
    }
    $filters = Get-NRFirewallFilterFromIndex -Rule $Rule -FilterIndex $FilterIndex
    return [pscustomobject]@{ name = $Name; rule = $body; filters = $filters }
}

function Write-NRFirewallRuleMappingProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [int] $Completed,
        [Parameter(Mandatory = $true)] [int] $Total,
        [Parameter(Mandatory = $true)] [int] $UpdateInterval
    )

    $isMilestone = ($Completed -eq 1) -or ($Completed -eq $Total) -or (($Completed % $UpdateInterval) -eq 0)
    if (-not $isMilestone) { return }

    $percent = [int](($Completed / $Total) * 100)
    $overallPercent = 10 + [int](($Completed / $Total) * 90)
    Write-Progress -Id 1 -Activity 'Capturing Firewall rules' `
        -Status ("Mapping Firewall rule filters: {0}/{1} ({2}%)" -f $Completed, $Total, $percent) `
        -PercentComplete $overallPercent
}

function Get-NRFirewallRules {
    [CmdletBinding()]
    param(
        [int] $ProgressParentId = -1,
        [ValidateSet('PersistentStore', 'SystemDefaults', 'StaticServiceStore', 'ConfigurableServiceStore')]
        [string] $PolicyStore = 'PersistentStore',
        [switch] $IncludeComparisonSource
    )

    $captureTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $startProgress = @{ Id = 1; Activity = 'Capturing Firewall rules'; Status = ("Enumerating {0} rules..." -f $PolicyStore); PercentComplete = 0 }
    if ($ProgressParentId -ge 0) { $startProgress.ParentId = $ProgressParentId }
    Write-Progress @startProgress
    try {
        $enumerationTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $rules = @(Get-NetFirewallRule -PolicyStore $PolicyStore -All -ErrorAction Stop)
        $enumerationTimer.Stop()
        $ruleCount = $rules.Count
        $ruleNames = @(Get-NRFirewallRuleNames -Rules $rules)
        if ($ruleCount -eq 0) {
            Write-Progress -Id 1 -Activity 'Capturing Firewall rules' `
                -Status ("No PersistentStore rules found ({0:N1}s)." -f $enumerationTimer.Elapsed.TotalSeconds) -PercentComplete 100
            if ($IncludeComparisonSource) {
                $emptyNativeIndexes = @{}
                foreach ($spec in @(Get-NRFirewallFilterSpecs)) { $emptyNativeIndexes[$spec.JsonName] = @{} }
                return [pscustomobject]@{
                    Records = @()
                    ComparisonSource = [pscustomobject]@{ PolicyStore = $PolicyStore; Rules = @(); FilterIndexes = $emptyNativeIndexes }
                }
            }
            return @()
        }

        Write-Progress -Id 1 -Activity 'Capturing Firewall rules' `
            -Status ("Found {0} rules in {1:N1}s; loading filter collections..." -f $ruleCount, $enumerationTimer.Elapsed.TotalSeconds) -PercentComplete 5
        if ($IncludeComparisonSource) {
            $filterIndexResult = Get-NRFirewallFilterIndex -RuleNames $ruleNames -PolicyStore $PolicyStore `
                -ShowProgress -IncludeNativeObjects
            $filterIndex = $filterIndexResult.RecordIndex
        }
        else {
            $filterIndex = Get-NRFirewallFilterIndex -RuleNames $ruleNames -PolicyStore $PolicyStore -ShowProgress
        }
        $result = New-Object 'System.Collections.Generic.List[object]'
        $updateInterval = [Math]::Max(1, [int][Math]::Ceiling($ruleCount / 100.0))

        for ($ruleIndex = 0; $ruleIndex -lt $ruleCount; $ruleIndex++) {
            $record = ConvertTo-NRFirewallRuleRecord -Rule $rules[$ruleIndex] `
                -Name $ruleNames[$ruleIndex] -FilterIndex $filterIndex
            $result.Add($record)
            Write-NRFirewallRuleMappingProgress -Completed ($ruleIndex + 1) -Total $ruleCount -UpdateInterval $updateInterval
        }

        $captureTimer.Stop()
        Write-Progress -Id 1 -Activity 'Capturing Firewall rules' `
            -Status ("Captured and mapped {0} Firewall rules ({1:N1}s total)." -f $ruleCount, $captureTimer.Elapsed.TotalSeconds) -PercentComplete 100
        if ($IncludeComparisonSource) {
            return [pscustomobject]@{
                Records = $result.ToArray()
                ComparisonSource = [pscustomobject]@{
                    PolicyStore = $PolicyStore
                    Rules = $rules
                    FilterIndexes = $filterIndexResult.NativeIndexes
                }
            }
        }
        return $result.ToArray()
    }
    finally {
        if ($captureTimer.IsRunning) { $captureTimer.Stop() }
        Write-Progress -Id 2 -ParentId 1 -Activity 'Loading Firewall filters' -Completed
        Write-Progress -Id 1 -Activity 'Capturing Firewall rules' -Completed
    }
}

function ConvertTo-NRFirewallDynamicKeywordAddressRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Address)

    $id = [string](Get-NRProperty $Address 'Id')
    if ([string]::IsNullOrWhiteSpace($id)) { throw 'A PersistentStore dynamic keyword address has an empty Id.' }

    $autoResolve = [bool](Get-NRProperty $Address 'AutoResolve')
    $addresses = if ($autoResolve) { $null } else { [string](Get-NRProperty $Address 'Addresses') }
    return [pscustomobject][ordered]@{
        id = $id
        Keyword = [string](Get-NRProperty $Address 'Keyword')
        Addresses = $addresses
        AutoResolve = $autoResolve
    }
}

function Get-NRFirewallDynamicKeywordAddresses {
    [CmdletBinding()]
    param()
    $items = @(Get-NetFirewallDynamicKeywordAddress -All -PolicyStore PersistentStore -ErrorAction Stop)
    $result = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $items) {
        $result.Add((ConvertTo-NRFirewallDynamicKeywordAddressRecord -Address $item))
    }
    return $result.ToArray()
}

function Get-NRFirewallProfiles {
    [CmdletBinding()]
    param()
    $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop)
    $result = [ordered]@{}
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $matchingProfiles = @($profiles | Where-Object { [string](Get-NRProperty $_ 'Name') -eq $name })
        if ($matchingProfiles.Count -ne 1) { throw "Expected exactly one PersistentStore firewall profile '$name'; got $($matchingProfiles.Count)." }
        $body = [ordered]@{}
        foreach ($field in $script:NRFirewallProfileFields) {
            if ($field -eq 'DisabledInterfaceAliases') { $body[$field] = Get-NRStringArrayFromObject -Object $matchingProfiles[0] -Name $field }
            else { $body[$field] = Get-NRValueFromObject -Object $matchingProfiles[0] -Name $field }
        }
        $result[$name] = $body
    }
    return $result
}

function ConvertTo-NRNrptRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Rule,
        [Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $LogicalId
    )

    $windowsName = [string](Get-NRProperty $Rule 'Name')
    if ([string]::IsNullOrWhiteSpace($windowsName)) { throw 'An NRPT rule has an empty Windows Name.' }
    if ([string]::IsNullOrWhiteSpace($LogicalId)) { throw "NRPT rule '$windowsName' has an empty logical id." }

    $mapping = [ordered]@{
        Namespace = 'Namespace'
        IPsecTrustAuthority = 'IPsecCARestriction'
        DANameServers = 'DirectAccessDnsServers'
        DAEnable = 'DirectAccessEnabled'
        DAIPsecEncryptionType = 'DirectAccessQueryIPsecEncryption'
        DAIPsecRequired = 'DirectAccessQueryIPsecRequired'
        DAProxyServerName = 'DirectAccessProxyName'
        DAProxyType = 'DirectAccessProxyType'
        NameServers = 'NameServers'
        NameEncoding = 'NameEncoding'
        DnsSecEnable = 'DnsSecEnabled'
        DnsSecIPsecEncryptionType = 'DnsSecQueryIPsecEncryption'
        DnsSecIPsecRequired = 'DnsSecQueryIPsecRequired'
        DnsSecValidationRequired = 'DnsSecValidationRequired'
        DisplayName = 'DisplayName'
        Comment = 'Comment'
    }

    $record = [ordered]@{ id = $LogicalId }
    foreach ($field in $script:NRNrptFields) {
        if ($field -in @('Namespace', 'DANameServers', 'NameServers')) {
            $record[$field] = Get-NRStringArrayFromObject -Object $Rule -Name $mapping[$field]
        }
        else {
            $record[$field] = Get-NRValueFromObject -Object $Rule -Name $mapping[$field]
        }
    }
    return [pscustomobject]$record
}

function Get-NRNrptRules {
    [CmdletBinding()]
    param([hashtable] $IdByWindowsName = @{})
    $rules = @(Get-DnsClientNrptRule -ErrorAction Stop)
    $result = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $rules) {
        $windowsName = [string](Get-NRProperty $rule 'Name')
        if ([string]::IsNullOrWhiteSpace($windowsName)) { throw 'An NRPT rule has an empty Windows Name.' }
        $id = if ($IdByWindowsName.ContainsKey($windowsName)) { [string]$IdByWindowsName[$windowsName] } else { $windowsName }
        $result.Add((ConvertTo-NRNrptRecord -Rule $rule -LogicalId $id))
    }
    return $result.ToArray()
}

function Get-NRCurrentState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $StatePath,
        [switch] $IncludeComparisonSource
    )

    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Progress -Id 0 -Activity 'Capturing network configuration' -Status 'Reading Firewall Profiles...' -PercentComplete 0
    try {
        $state = Read-NRStateFile -Path $StatePath
        $idByName = @{}
        foreach ($id in @($state.nrptRules.Keys)) { $idByName[[string]$state.nrptRules[$id]] = [string]$id }

        $stageTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $profiles = Get-NRFirewallProfiles
        $stageTimer.Stop()
        Write-Progress -Id 0 -Activity 'Capturing network configuration' `
            -Status ("Read {0} Firewall Profiles ({1:N1}s)." -f $profiles.Count, $stageTimer.Elapsed.TotalSeconds) -PercentComplete 10

        $stageTimer.Restart()
        $dynamicAddresses = @(Get-NRFirewallDynamicKeywordAddresses)
        $stageTimer.Stop()
        Write-Progress -Id 0 -Activity 'Capturing network configuration' `
            -Status ("Read {0} Firewall Dynamic Keyword Addresses ({1:N1}s)." -f $dynamicAddresses.Count, $stageTimer.Elapsed.TotalSeconds) -PercentComplete 20

        $stageTimer.Restart()
        if ($IncludeComparisonSource) {
            $firewallCapture = Get-NRFirewallRules -ProgressParentId 0 -IncludeComparisonSource
            $firewallRules = @($firewallCapture.Records)
            $comparisonSource = $firewallCapture.ComparisonSource
        }
        else {
            $firewallRules = @(Get-NRFirewallRules -ProgressParentId 0)
        }
        $stageTimer.Stop()
        Write-Progress -Id 0 -Activity 'Capturing network configuration' `
            -Status ("Read {0} Firewall rules and associated filters ({1:N1}s)." -f $firewallRules.Count, $stageTimer.Elapsed.TotalSeconds) -PercentComplete 90

        $stageTimer.Restart()
        $nrptRules = @(Get-NRNrptRules -IdByWindowsName $idByName)
        $stageTimer.Stop()
        Write-Progress -Id 0 -Activity 'Capturing network configuration' `
            -Status ("Read {0} local NRPT rules ({1:N1}s)." -f $nrptRules.Count, $stageTimer.Elapsed.TotalSeconds) -PercentComplete 100

        $configuration = [pscustomobject][ordered]@{
            schemaVersion = 1
            firewallProfiles = $profiles
            firewallDynamicKeywordAddresses = $dynamicAddresses
            firewallRules = $firewallRules
            nrptRules = $nrptRules
        }
        if ($IncludeComparisonSource) {
            return [pscustomobject]@{ Configuration = $configuration; ComparisonSource = $comparisonSource }
        }
        return $configuration
    }
    finally {
        $totalTimer.Stop()
        Write-Progress -Id 2 -ParentId 1 -Activity 'Loading Firewall filters' -Completed
        Write-Progress -Id 1 -Activity 'Capturing Firewall rules' -Completed
        Write-Progress -Id 0 -Activity 'Capturing network configuration' `
            -Status ("Capture enumeration finished ({0:N1}s)." -f $totalTimer.Elapsed.TotalSeconds) -Completed
    }
}

$script:NRComparisonExcludedProperties = @(
    'Name', 'InstanceID', 'PolicyStore', 'PolicyStoreSource', 'PolicyStoreSourceType',
    'PrimaryStatus', 'Status', 'EnforcementStatus', 'PSComputerName',
    'CimClass', 'CimInstanceProperties', 'CimSystemProperties'
)

$script:NRComparisonFilterDefinitions = @(
    [pscustomobject]@{ Key = 'Address';       JsonName = 'address';       Command = 'Get-NetFirewallAddressFilter' },
    [pscustomobject]@{ Key = 'Application';   JsonName = 'application';   Command = 'Get-NetFirewallApplicationFilter' },
    [pscustomobject]@{ Key = 'Port';          JsonName = 'port';          Command = 'Get-NetFirewallPortFilter' },
    [pscustomobject]@{ Key = 'Service';       JsonName = 'service';       Command = 'Get-NetFirewallServiceFilter' },
    [pscustomobject]@{ Key = 'Interface';     JsonName = 'interface';     Command = 'Get-NetFirewallInterfaceFilter' },
    [pscustomobject]@{ Key = 'InterfaceType'; JsonName = 'interfaceType'; Command = 'Get-NetFirewallInterfaceTypeFilter' },
    [pscustomobject]@{ Key = 'Security';      JsonName = 'security';      Command = 'Get-NetFirewallSecurityFilter' }
)

function ConvertTo-NRComparisonCimValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [Microsoft.Management.Infrastructure.CimInstance] $Value)
    $result = [ordered]@{}
    foreach ($property in $Value.CimInstanceProperties) {
        $result[[string]$property.Name] = ConvertTo-NRComparisonPlainValue $property.Value
    }
    return $result
}

function ConvertTo-NRComparisonDictionaryValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [System.Collections.IDictionary] $Value)
    $result = [ordered]@{}
    foreach ($key in @($Value.Keys | Sort-Object)) {
        $result[[string]$key] = ConvertTo-NRComparisonPlainValue $Value[$key]
    }
    return $result
}

function ConvertTo-NRComparisonSequenceValue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [System.Collections.IEnumerable] $Value)
    $items = New-Object System.Collections.ArrayList
    foreach ($item in $Value) { $null = $items.Add((ConvertTo-NRComparisonPlainValue $item)) }
    return ,($items.ToArray())
}

function ConvertTo-NRComparisonPlainValue {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [Microsoft.Management.Infrastructure.CimInstance]) { return ConvertTo-NRComparisonCimValue -Value $Value }
    if ($Value -is [System.Collections.IDictionary]) { return ConvertTo-NRComparisonDictionaryValue -Value $Value }
    if ($Value -is [System.Array] -or $Value -is [System.Collections.ArrayList]) { return ConvertTo-NRComparisonSequenceValue -Value $Value }
    if ($Value -is [datetime]) { return $Value.ToString('o') }
    if ($Value -is [System.Enum]) { return $Value.ToString() }
    return $Value
}

function ConvertTo-NRComparisonCanonicalPlainValue {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [System.Array] -or $Value -is [System.Collections.ArrayList]) {
        $items = New-Object 'System.Collections.Generic.List[string]'
        foreach ($item in $Value) {
            if ($item -is [System.Array] -or $item -is [System.Collections.ArrayList]) {
                $canonicalItem = ConvertTo-NRComparisonCanonicalPlainValue -Value $item
            }
            else {
                $canonicalItem = ConvertTo-Json -InputObject $item -Depth 40 -Compress
            }
            $items.Add([string]$canonicalItem)
        }
        $items.Sort([System.StringComparer]::Ordinal)
        return '[' + [string]::Join(',', $items.ToArray()) + ']'
    }
    return (ConvertTo-Json -InputObject $Value -Depth 40 -Compress)
}

function Get-NRComparisonProperties {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $InputObject,
        [Parameter(Mandatory = $true)] [string] $Section
    )

    $result = @{}
    if ($InputObject -is [Microsoft.Management.Infrastructure.CimInstance]) {
        $properties = $InputObject.CimInstanceProperties
    }
    else {
        $properties = $InputObject.PSObject.Properties
    }

    foreach ($property in $properties) {
        $name = [string]$property.Name
        if ([string]::IsNullOrWhiteSpace($name) -or $script:NRComparisonExcludedProperties -contains $name) { continue }
        $memberTypeProperty = $property.PSObject.Properties['MemberType']
        if ($null -ne $memberTypeProperty -and $property.MemberType -notin @('Property', 'NoteProperty', 'AliasProperty')) { continue }

        # Store the normalized value for each comparison property. Canonical
        # JSON is created during comparison only when a value needs the complex
        # fallback; ordinary scalar values remain directly comparable.
        $value = $property.Value
        $plainValue = $value
        if ($null -eq $value) {
            $plainValue = $null
        }
        elseif ($value -is [datetime]) {
            $plainValue = $value.ToString('o')
        }
        elseif ($value -is [System.Enum]) {
            $plainValue = $value.ToString()
        }
        elseif ($value -is [Microsoft.Management.Infrastructure.CimInstance] -or
            $value -is [System.Collections.IDictionary] -or
            $value -is [System.Array] -or
            $value -is [System.Collections.ArrayList]) {
            $plainValue = ConvertTo-NRComparisonPlainValue -Value $value
        }

        $result[('{0}.{1}' -f $Section, $name)] = [pscustomobject]@{ Value = $plainValue }
    }
    return ,$result
}

function Get-NRComparisonFilterIndex {
    [CmdletBinding()]
    param([string] $PolicyStore, [object] $Definition)
    $index = @{}
    try {
        $filters = @(& $Definition.Command -PolicyStore $PolicyStore -All -ErrorAction Stop)
        foreach ($filter in $filters) {
            # A bulk result without InstanceID cannot be joined to a Rule.
            # Ignore that item; the per-Rule lookup can report an association
            # issue if the Rule has no usable Filter.
            $instanceId = [string](Get-NRProperty -InputObject $filter -Name 'InstanceID')
            if ([string]::IsNullOrWhiteSpace($instanceId)) { continue }
            if (-not $index.ContainsKey($instanceId)) { $index[$instanceId] = New-Object System.Collections.ArrayList }
            $null = $index[$instanceId].Add($filter)
        }
        return [pscustomobject]@{ Index = $index; Warning = $null }
    }
    catch {
        return [pscustomobject]@{
            Index = $index
            Warning = [pscustomobject]@{ Filter = $Definition.Key; Detail = $_.Exception.Message }
        }
    }
}

function Get-NRRuleComparisonFilter {
    [CmdletBinding()]
    param([object] $Rule, [object] $Definition, [hashtable] $Index)
    $instanceId = [string]$Rule.InstanceID
    if (-not [string]::IsNullOrWhiteSpace($instanceId) -and $Index.ContainsKey($instanceId)) {
        $bucket = @($Index[$instanceId].ToArray())
        if ($bucket.Count -eq 1) { return [pscustomobject]@{ Filter = $bucket[0]; Issue = $null } }
    }
    try {
        $fallback = @(& $Definition.Command -AssociatedNetFirewallRule $Rule -ErrorAction Stop)
        if ($fallback.Count -eq 1) { return [pscustomobject]@{ Filter = $fallback[0]; Issue = $null } }
        $detail = if ($fallback.Count -eq 0) { 'No filter object returned by associated-rule query.' } else { 'Associated-rule query returned multiple filter objects.' }
        return [pscustomobject]@{ Filter = $null; Issue = [pscustomobject]@{ Filter = $Definition.Key; Detail = $detail } }
    }
    catch {
        return [pscustomobject]@{ Filter = $null; Issue = [pscustomobject]@{ Filter = $Definition.Key; Detail = $_.Exception.Message } }
    }
}

function ConvertTo-NRComparisonFilterIndexesFromCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [hashtable] $NativeFilterIndexes)
    $indexes = @{}
    foreach ($definition in $script:NRComparisonFilterDefinitions) {
        $index = @{}
        $nativeIndex = $NativeFilterIndexes[$definition.JsonName]
        if ($null -ne $nativeIndex) {
            foreach ($instanceId in $nativeIndex.Keys) {
                $bucket = New-Object System.Collections.ArrayList
                $null = $bucket.Add($nativeIndex[$instanceId])
                $index[[string]$instanceId] = $bucket
            }
        }
        $indexes[$definition.Key] = $index
    }
    return ,$indexes
}

function Get-NRFirewallRuleComparisonSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $PolicyStore,
        [AllowNull()] [object] $CaptureSource
    )

    $warnings = New-Object System.Collections.ArrayList
    if ($null -eq $CaptureSource) {
        $rules = @(Get-NetFirewallRule -PolicyStore $PolicyStore -All -ErrorAction Stop)
        $filterIndexes = Get-NRFirewallRuleComparisonIndexes -PolicyStore $PolicyStore -Warnings $warnings
    }
    else {
        if ([string]$CaptureSource.PolicyStore -cne $PolicyStore) {
            throw ("Capture source PolicyStore '{0}' does not match requested PolicyStore '{1}'." -f $CaptureSource.PolicyStore, $PolicyStore)
        }
        $rules = @($CaptureSource.Rules)
        $filterIndexes = ConvertTo-NRComparisonFilterIndexesFromCapture -NativeFilterIndexes $CaptureSource.FilterIndexes
    }

    return [pscustomobject]@{
        Rules = $rules
        FilterIndexes = $filterIndexes
        Warnings = $warnings.ToArray()
    }
}

function Get-NRFirewallRuleComparisonIndexes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $PolicyStore,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [System.Collections.ArrayList] $Warnings
    )

    $filterIndexes = @{}
    foreach ($definition in $script:NRComparisonFilterDefinitions) {
        $indexResult = Get-NRComparisonFilterIndex -PolicyStore $PolicyStore -Definition $definition
        $filterIndexes[$definition.Key] = $indexResult.Index
        if ($null -ne $indexResult.Warning) { $null = $Warnings.Add($indexResult.Warning) }
    }
    return $filterIndexes
}

function ConvertTo-NRFirewallRuleComparisonEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Rule,
        [Parameter(Mandatory = $true)] [hashtable] $FilterIndexes
    )

    $fields = Get-NRComparisonProperties -InputObject $Rule -Section 'Rule'
    $missing = New-Object 'System.Collections.Generic.List[string]'
    $issues = New-Object 'System.Collections.Generic.List[object]'
    foreach ($definition in $script:NRComparisonFilterDefinitions) {
        $filterResult = Get-NRRuleComparisonFilter -Rule $Rule -Definition $definition -Index $FilterIndexes[$definition.Key]
        if ($null -eq $filterResult.Filter) {
            $missing.Add($definition.Key)
            $issues.Add($filterResult.Issue)
            continue
        }
        $filterFields = Get-NRComparisonProperties -InputObject $filterResult.Filter -Section $definition.Key
        foreach ($fieldName in $filterFields.Keys) { $fields[$fieldName] = $filterFields[$fieldName] }
    }

    return [pscustomobject]@{
        Name = [string]$Rule.Name
        IsComplete = ($missing.Count -eq 0)
        MissingFilters = $missing.ToArray()
        FilterIssues = $issues.ToArray()
        Fields = $fields
    }
}

function Write-NRFirewallRuleComparisonProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $PolicyStore,
        [Parameter(Mandatory = $true)] [int] $Completed,
        [Parameter(Mandatory = $true)] [int] $Total,
        [switch] $Complete
    )

    if ($Complete) {
        Write-Progress -Id 1 -ParentId 0 -Activity ("Building {0} comparison inventory" -f $PolicyStore) -Completed
        return
    }

    $percent = if ($Total -gt 0) { [int](($Completed / $Total) * 100) } else { 100 }
    $status = if ($Total -gt 0) {
        "Projecting rule and filter properties: {0}/{1} ({2}%)" -f $Completed, $Total, $percent
    }
    else {
        'No rules to project.'
    }
    Write-Progress -Id 1 -ParentId 0 -Activity ("Building {0} comparison inventory" -f $PolicyStore) `
        -Status $status -PercentComplete $percent
}

function Get-NRFirewallRuleComparisonInventory {
    [CmdletBinding()]
    param(
        [ValidateSet('PersistentStore', 'SystemDefaults', 'StaticServiceStore', 'ConfigurableServiceStore')] [string] $PolicyStore,
        [AllowNull()] [object] $CaptureSource,
        [switch] $ShowProgress
    )

    $source = Get-NRFirewallRuleComparisonSource -PolicyStore $PolicyStore -CaptureSource $CaptureSource
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $total = $source.Rules.Count
    $updateInterval = [Math]::Max(1, [int][Math]::Ceiling($total / 100.0))
    if ($ShowProgress) {
        Write-NRFirewallRuleComparisonProgress -PolicyStore $PolicyStore -Completed 0 -Total $total
    }
    for ($ruleIndex = 0; $ruleIndex -lt $total; $ruleIndex++) {
        $entry = ConvertTo-NRFirewallRuleComparisonEntry -Rule $source.Rules[$ruleIndex] -FilterIndexes $source.FilterIndexes
        $entries.Add($entry)
        $completed = $ruleIndex + 1
        $isMilestone = ($completed -eq 1) -or ($completed -eq $total) -or (($completed % $updateInterval) -eq 0)
        if ($ShowProgress -and $isMilestone) {
            Write-NRFirewallRuleComparisonProgress -PolicyStore $PolicyStore -Completed $completed -Total $total
        }
    }
    if ($ShowProgress) {
        Write-NRFirewallRuleComparisonProgress -PolicyStore $PolicyStore -Completed $total -Total $total -Complete
    }

    return [pscustomobject]@{
        PolicyStore = $PolicyStore
        RuleCount = $total
        Entries = @($entries.ToArray() | Sort-Object Name)
        BulkFilterWarnings = $source.Warnings
    }
}

function Get-NRComparisonFieldValue {
    [CmdletBinding()]
    param([AllowNull()] [object] $Field)

    if ($null -eq $Field) { return $null }
    if ($Field -is [System.Management.Automation.PSCustomObject]) {
        $valueProperty = $Field.PSObject.Properties['Value']
        if ($null -ne $valueProperty) { return ,$valueProperty.Value }
    }
    elseif ($Field -is [System.Collections.IDictionary] -and $Field.Contains('Value')) {
        return ,$Field['Value']
    }
    return $null
}

function Test-NRComparisonPlainValuesEqual {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $Left,
        [AllowNull()] [object] $Right
    )

    if ($null -eq $Left -or $null -eq $Right) { return ($null -eq $Left -and $null -eq $Right) }
    if ($Left -is [string] -and $Right -is [string]) { return ($Left -ceq $Right) }
    if ($Left -is [bool] -and $Right -is [bool]) { return ($Left -eq $Right) }

    $leftIsSequence = ($Left -is [System.Array] -or $Left -is [System.Collections.ArrayList])
    $rightIsSequence = ($Right -is [System.Array] -or $Right -is [System.Collections.ArrayList])
    if ($leftIsSequence -and $rightIsSequence) {
        $stringSequenceEqual = Test-NRStringSequenceEqual -Left $Left -Right $Right
        if ($null -ne $stringSequenceEqual) { return [bool]$stringSequenceEqual }
    }
    elseif ($Left.GetType() -eq $Right.GetType() -and $Left -is [System.ValueType]) {
        return $Left.Equals($Right)
    }

    # Compare complex values consistently with Snapshot creation: dictionary
    # keys and array items are canonicalized, array duplicates are retained,
    # and string values remain case-sensitive.
    $leftCanonical = ConvertTo-NRComparisonCanonicalPlainValue -Value $Left
    $rightCanonical = ConvertTo-NRComparisonCanonicalPlainValue -Value $Right
    return ([string]$leftCanonical -ceq [string]$rightCanonical)
}

function Test-NRComparisonFieldValuesEqual {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $PersistentField,
        [AllowNull()] [object] $DefaultField
    )

    $persistentValue = Get-NRComparisonFieldValue -Field $PersistentField
    $defaultValue = Get-NRComparisonFieldValue -Field $DefaultField
    return (Test-NRComparisonPlainValuesEqual -Left $persistentValue -Right $defaultValue)
}

function Test-NRValueOnlyComparisonFieldsEqual {
    param([object] $PersistentField, [object] $DefaultField)
    if ($PersistentField -isnot [System.Management.Automation.PSCustomObject] -or
        $DefaultField -isnot [System.Management.Automation.PSCustomObject]) { return $null }
    $persistentValue = $PersistentField.PSObject.Properties['Value']
    $defaultValue = $DefaultField.PSObject.Properties['Value']
    if ($null -eq $persistentValue -or $null -eq $defaultValue) { return $null }
    return (Test-NRComparisonPlainValuesEqual -Left $persistentValue.Value -Right $defaultValue.Value)
}

function Test-NRPCustomObjectComparisonFieldsEqual {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $PersistentFields,
        [AllowNull()] [object] $DefaultFields
    )
    $persistentProperties = @($PersistentFields.PSObject.Properties)
    $defaultPropertyCount = @($DefaultFields.PSObject.Properties).Count
    if ($persistentProperties.Count -ne $defaultPropertyCount) { return $false }

    foreach ($persistentProperty in $persistentProperties) {
        $defaultProperty = $DefaultFields.PSObject.Properties[$persistentProperty.Name]
        if ($null -eq $defaultProperty) { return $false }
        $fastResult = Test-NRValueOnlyComparisonFieldsEqual -PersistentField $persistentProperty.Value -DefaultField $defaultProperty.Value
        if ($null -ne $fastResult) {
            if (-not $fastResult) { return $false }
            continue
        }
        if (-not (Test-NRComparisonFieldValuesEqual -PersistentField $persistentProperty.Value -DefaultField $defaultProperty.Value)) {
            return $false
        }
    }
    return $true
}

function Test-NRGeneralComparisonFieldsEqual {
    [CmdletBinding()]
    param(
        [AllowNull()] [object] $PersistentFields,
        [AllowNull()] [object] $DefaultFields
    )

    $fieldNames = @(@(Get-NRPropertyNames $PersistentFields) + @(Get-NRPropertyNames $DefaultFields) | Select-Object -Unique)
    foreach ($fieldName in $fieldNames) {
        if (-not (Test-NRProperty $PersistentFields $fieldName) -or -not (Test-NRProperty $DefaultFields $fieldName)) { return $false }
        $persistentField = Get-NRProperty $PersistentFields $fieldName
        $defaultField = Get-NRProperty $DefaultFields $fieldName
        if (-not (Test-NRComparisonFieldValuesEqual -PersistentField $persistentField -DefaultField $defaultField)) { return $false }
    }
    return $true
}

function Get-NRComparisonEntryFields {
    param([AllowNull()] [object] $Entry)
    if ($null -eq $Entry) { return $null }
    if ($Entry -is [System.Management.Automation.PSCustomObject]) {
        $member = $Entry.PSObject.Properties['Fields']
        if ($null -eq $member) { return $null }
        return ,$member.Value
    }
    return ,(Get-NRProperty $Entry 'Fields')
}

function Get-NRDefaultRuleStatus {
    [CmdletBinding()]
    param(
        [string] $Name,
        [hashtable] $PersistentComparisonByName,
        [hashtable] $SystemDefaultsByName
    )
    if (-not $SystemDefaultsByName.ContainsKey($Name)) { return 'NotFound' }
    if (-not $PersistentComparisonByName.ContainsKey($Name)) { return 'Inconclusive' }
    $persistentEntry = $PersistentComparisonByName[$Name]
    $defaultEntry = $SystemDefaultsByName[$Name]
    if (-not $persistentEntry.IsComplete -or -not $defaultEntry.IsComplete) { return 'Inconclusive' }

    $persistentFields = Get-NRComparisonEntryFields -Entry $persistentEntry
    $defaultFields = Get-NRComparisonEntryFields -Entry $defaultEntry
    if ($persistentFields -is [System.Management.Automation.PSCustomObject] -and
        $defaultFields -is [System.Management.Automation.PSCustomObject]) {
        if (Test-NRPCustomObjectComparisonFieldsEqual -PersistentFields $persistentFields -DefaultFields $defaultFields) {
            return 'ExactMatch'
        }
        return 'Mismatch'
    }
    if (Test-NRGeneralComparisonFieldsEqual -PersistentFields $persistentFields -DefaultFields $defaultFields) {
        return 'ExactMatch'
    }
    return 'Mismatch'
}

function Get-NRCurrentCaptureState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $StatePath)
    $captureState = Get-NRCurrentState -StatePath $StatePath -IncludeComparisonSource
    if (Test-NRProperty -InputObject $captureState -Name 'Configuration') { return $captureState }
    return [pscustomobject]@{ Configuration = $captureState; ComparisonSource = $null }
}

function New-NRCaptureSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $StatePath)
    $captureState = Get-NRCurrentCaptureState -StatePath $StatePath
    $configuration = $captureState.Configuration
    Write-Progress -Id 0 -Activity 'Capturing network configuration' -Status 'Preparing PersistentStore comparison...' -PercentComplete 92
    if ($null -ne $captureState.ComparisonSource) {
        # Reuse the native PersistentStore Rules and seven Filter collections
        # already collected for the configuration; do not query them again.
        $persistentComparison = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore `
            -CaptureSource $captureState.ComparisonSource -ShowProgress
    }
    else {
        $persistentComparison = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore -ShowProgress
    }
    Write-Progress -Id 0 -Activity 'Capturing network configuration' -Status 'Preparing SystemDefaults comparison...' -PercentComplete 95
    $defaultsComparison = Get-NRFirewallRuleComparisonInventory -PolicyStore SystemDefaults -ShowProgress

    Write-Progress -Id 0 -Activity 'Capturing network configuration' -Status 'Validating comparison results...' -PercentComplete 98

    $persistentIncomplete = @($persistentComparison.Entries | Where-Object { -not $_.IsComplete })
    $defaultsIncomplete = @($defaultsComparison.Entries | Where-Object { -not $_.IsComplete })
    if ($persistentIncomplete.Count -gt 0 -or $defaultsIncomplete.Count -gt 0) {
        throw ('Cannot create a comparable snapshot: PersistentStore incomplete rules={0}; SystemDefaults incomplete rules={1}.' -f `
            $persistentIncomplete.Count, $defaultsIncomplete.Count)
    }

    $configurationNames = Get-NRMapByKey -Items @($configuration.firewallRules) -KeyProperty 'name'
    $comparisonNames = Get-NRMapByKey -Items @($persistentComparison.Entries) -KeyProperty 'Name'
    if ($configurationNames.Count -ne $comparisonNames.Count -or
        @($configurationNames.Keys | Where-Object { -not $comparisonNames.ContainsKey($_) }).Count -gt 0) {
        throw 'PersistentStore configuration capture and comparison inventory do not contain the same rule Names.'
    }
    $null = Get-NRMapByKey -Items @($defaultsComparison.Entries) -KeyProperty 'Name'

    return [pscustomobject][ordered]@{
        schemaVersion = 1
        capturedAt = (Get-Date).ToString('o')
        computerName = $env:COMPUTERNAME
        configuration = $configuration
        comparison = [pscustomobject]@{
            persistentStore = $persistentComparison
            systemDefaults = $defaultsComparison
            excludedProperties = @($script:NRComparisonExcludedProperties)
            arraySemantics = 'Array order is ignored; duplicate elements are retained.'
            stringSemantics = 'String values are compared case-sensitively.'
        }
    }
}

function Get-NRFirewallRuleDisplayInfo {
    [CmdletBinding()]
    param([AllowNull()] [object] $Record)
    $rule = Get-NRProperty $Record 'rule'
    $filters = Get-NRProperty $Record 'filters'
    $application = Get-NRProperty $filters 'application'
    $service = Get-NRProperty $filters 'service'
    return [pscustomobject]@{
        DisplayName = Get-NRProperty $rule 'DisplayName'
        Group = Get-NRProperty $rule 'Group'
        Program = Get-NRProperty $application 'Program'
        Package = Get-NRProperty $application 'Package'
        Service = Get-NRProperty $service 'Service'
    }
}

function ConvertTo-NRObjectArray {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    while ($Value -is [System.Array] -and $Value.Count -eq 1 -and $Value[0] -is [System.Array]) {
        $Value = $Value[0]
    }
    if ($null -eq $Value) { return }
    if ($Value -is [System.Array]) { return $Value }
    return $Value
}

function New-NRFirewallClassificationRecord {
    [CmdletBinding()]
    param([string] $Name, [string] $Status, [string] $Management, [string] $DefaultStatus, [object[]] $Details, [object] $Record)
    $displayInfo = Get-NRFirewallRuleDisplayInfo -Record $Record
    return [pscustomobject]@{
        Name = $Name
        Status = $Status
        Management = $Management
        SystemDefaults = $DefaultStatus
        Details = @($Details)
        DisplayName = $displayInfo.DisplayName
        Group = $displayInfo.Group
        Program = $displayInfo.Program
        Package = $displayInfo.Package
        Service = $displayInfo.Service
    }
}

function Get-NRManagedFirewallClassifications {
    [CmdletBinding()]
    param([hashtable] $DesiredByName, [hashtable] $CurrentByName, [hashtable] $PersistentByName, [hashtable] $DefaultsByName)
    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in @($DesiredByName.Keys | Sort-Object)) {
        $exists = $CurrentByName.ContainsKey($name)
        $defaultStatus = if ($exists) { Get-NRDefaultRuleStatus -Name $name -PersistentComparisonByName $PersistentByName -SystemDefaultsByName $DefaultsByName } else { 'Unavailable' }
        if ($exists) {
            $record = $CurrentByName[$name]
            $details = @(Get-NRObjectChanges -Before $record -After $DesiredByName[$name])
            $status = if ($details.Count -eq 0) { 'InSync' } else { 'Modified' }
        }
        else {
            $record = $DesiredByName[$name]
            $details = @('Rule does not exist in the latest capture snapshot.')
            $status = 'Missing'
        }
        $results.Add((New-NRFirewallClassificationRecord -Name $name -Status $status -Management 'Managed' -DefaultStatus $defaultStatus -Details $details -Record $record))
    }
    return $results.ToArray()
}

function Get-NRRemovedManagedFirewallClassifications {
    [CmdletBinding()]
    param([string[]] $ManagedNames, [hashtable] $DesiredByName, [hashtable] $CurrentByName, [hashtable] $ExcludedByName = @{})
    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in @($ManagedNames | Where-Object { -not $DesiredByName.ContainsKey([string]$_) -and -not $ExcludedByName.ContainsKey([string]$_) } | Sort-Object)) {
        $key = [string]$name
        $exists = $CurrentByName.ContainsKey($key)
        $status = if ($exists) { 'DeletePending' } else { 'DeleteComplete' }
        $record = if ($exists) { $CurrentByName[$key] } else { $null }
        $results.Add((New-NRFirewallClassificationRecord -Name $key -Status $status -Management 'Managed' -DefaultStatus 'NotEvaluated' -Details @() -Record $record))
    }
    return $results.ToArray()
}

function Get-NRUnmanagedFirewallClassifications {
    [CmdletBinding()]
    param([hashtable] $CurrentByName, [hashtable] $Managed, [hashtable] $PersistentByName, [hashtable] $DefaultsByName, [hashtable] $ExcludedByName = @{})
    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in @($CurrentByName.Keys | Where-Object { -not $Managed.ContainsKey([string]$_) -and -not $ExcludedByName.ContainsKey([string]$_) } | Sort-Object)) {
        $key = [string]$name
        $defaultStatus = Get-NRDefaultRuleStatus -Name $key -PersistentComparisonByName $PersistentByName -SystemDefaultsByName $DefaultsByName
        $status = if ($defaultStatus -eq 'ExactMatch') { 'DefaultExcluded' } elseif ($defaultStatus -eq 'Inconclusive') { 'ComparisonInconclusive' } else { 'NewCandidate' }
        $results.Add((New-NRFirewallClassificationRecord -Name $key -Status $status -Management 'Unmanaged' -DefaultStatus $defaultStatus -Details @() -Record $CurrentByName[$key]))
    }
    return $results.ToArray()
}

function Get-NRExcludedFirewallClassifications {
    [CmdletBinding()]
    param([string[]] $ExcludedNames, [hashtable] $CurrentByName)
    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($name in @($ExcludedNames | Sort-Object)) {
        $key = [string]$name
        $exists = $CurrentByName.ContainsKey($key)
        $status = if ($exists) { 'Excluded' } else { 'ExcludedMissing' }
        $record = if ($exists) { $CurrentByName[$key] } else { $null }
        $results.Add((New-NRFirewallClassificationRecord -Name $key -Status $status -Management 'Excluded' `
            -DefaultStatus 'NotEvaluated' -Details @() -Record $record))
    }
    return $results.ToArray()
}

function Get-NRFirewallRuleRenameComparableRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Record)

    $properties = [ordered]@{}
    foreach ($propertyName in @(Get-NRPropertyNames $Record)) {
        if ($propertyName -ieq 'name') { continue }
        $value = Get-NRProperty $Record $propertyName
        if ($propertyName -ieq 'rule' -and $null -ne $value) {
            $ruleProperties = [ordered]@{}
            foreach ($rulePropertyName in @(Get-NRPropertyNames $value)) {
                if ($rulePropertyName -ine 'name') {
                    $ruleProperties[$rulePropertyName] = Get-NRProperty $value $rulePropertyName
                }
            }
            $value = [pscustomobject]$ruleProperties
        }
        $properties[$propertyName] = $value
    }
    return [pscustomobject]$properties
}

function Test-NRFirewallRuleRenameEquivalent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Before,
        [Parameter(Mandatory = $true)] [object] $After
    )

    $beforeComparable = Get-NRFirewallRuleRenameComparableRecord -Record $Before
    $afterComparable = Get-NRFirewallRuleRenameComparableRecord -Record $After
    return (@(Get-NRObjectChanges -Before $beforeComparable -After $afterComparable).Count -eq 0)
}

function Add-NRFirewallRuleRenameMatch {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]] $MatchList,
        [hashtable] $MissingMatchCounts,
        [hashtable] $CandidateMatchCounts,
        [string] $OldName,
        [string] $NewName,
        [string] $SystemDefaults
    )

    $MatchList.Add([pscustomobject]@{ OldName = $OldName; NewName = $NewName; SystemDefaults = $SystemDefaults })
    if (-not $MissingMatchCounts.ContainsKey($OldName)) { $MissingMatchCounts[$OldName] = 0 }
    if (-not $CandidateMatchCounts.ContainsKey($NewName)) { $CandidateMatchCounts[$NewName] = 0 }
    $MissingMatchCounts[$OldName]++
    $CandidateMatchCounts[$NewName]++
}

function Get-NRFirewallRuleRenameMatchInventory {
    [CmdletBinding()]
    param(
        [object[]] $MissingItems,
        [object[]] $CandidateItems,
        [hashtable] $DesiredByName,
        [hashtable] $CurrentByName
    )

    $matchList = New-Object 'System.Collections.Generic.List[object]'
    $missingMatchCounts = @{}
    $candidateMatchCounts = @{}
    foreach ($missingItem in $MissingItems) {
        $oldName = [string]$missingItem.Name
        foreach ($candidateItem in $CandidateItems) {
            $newName = [string]$candidateItem.Name
            if (Test-NRFirewallRuleRenameEquivalent -Before $DesiredByName[$oldName] -After $CurrentByName[$newName]) {
                Add-NRFirewallRuleRenameMatch -MatchList $matchList -MissingMatchCounts $missingMatchCounts `
                    -CandidateMatchCounts $candidateMatchCounts -OldName $oldName -NewName $newName `
                    -SystemDefaults ([string]$candidateItem.SystemDefaults)
            }
        }
    }
    return [pscustomobject]@{
        CandidateMatches = @($matchList.ToArray())
        MissingMatchCounts = $missingMatchCounts
        CandidateMatchCounts = $candidateMatchCounts
    }
}

function Get-NRUniqueFirewallRuleRenamePairs {
    [CmdletBinding()]
    param(
        [object[]] $CandidateMatches,
        [hashtable] $MissingMatchCounts,
        [hashtable] $CandidateMatchCounts
    )

    $renames = New-Object 'System.Collections.Generic.List[object]'
    foreach ($match in $CandidateMatches) {
        if ($MissingMatchCounts[$match.OldName] -eq 1 -and $CandidateMatchCounts[$match.NewName] -eq 1) {
            $renames.Add($match)
        }
    }
    return @($renames.ToArray() | Sort-Object OldName, NewName)
}

function Get-NRFirewallRuleRenamePairs {
    [CmdletBinding()]
    param(
        [object[]] $Classifications,
        [hashtable] $DesiredByName,
        [hashtable] $CurrentByName
    )

    $missingItems = @($Classifications | Where-Object Status -eq 'Missing')
    $candidateItems = @($Classifications | Where-Object Status -eq 'NewCandidate')
    $inventory = Get-NRFirewallRuleRenameMatchInventory -MissingItems $missingItems -CandidateItems $candidateItems `
        -DesiredByName $DesiredByName -CurrentByName $CurrentByName
    return @(Get-NRUniqueFirewallRuleRenamePairs -CandidateMatches $inventory.CandidateMatches `
        -MissingMatchCounts $inventory.MissingMatchCounts -CandidateMatchCounts $inventory.CandidateMatchCounts)
}

function Add-NRFirewallRuleRenameClassifications {
    [CmdletBinding()]
    param(
        [object[]] $Classifications,
        [hashtable] $DesiredByName,
        [hashtable] $CurrentByName
    )

    $renames = @(Get-NRFirewallRuleRenamePairs -Classifications $Classifications -DesiredByName $DesiredByName -CurrentByName $CurrentByName)
    if ($renames.Count -eq 0) { return $Classifications }
    $renamedOldNames = @{}
    $renamedNewNames = @{}
    foreach ($rename in $renames) {
        $renamedOldNames[[string]$rename.OldName] = $true
        $renamedNewNames[[string]$rename.NewName] = $true
    }

    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $Classifications) {
        $isRenamedMissing = ($item.Status -eq 'Missing' -and $renamedOldNames.ContainsKey([string]$item.Name))
        $isRenamedCandidate = ($item.Status -eq 'NewCandidate' -and $renamedNewNames.ContainsKey([string]$item.Name))
        if (-not $isRenamedMissing -and -not $isRenamedCandidate) { $results.Add($item) }
    }
    foreach ($rename in $renames) {
        $record = New-NRFirewallClassificationRecord -Name $rename.OldName -Status 'Rename' -Management 'Managed' `
            -DefaultStatus $rename.SystemDefaults -Details @() -Record $CurrentByName[$rename.NewName]
        $record | Add-Member -MemberType NoteProperty -Name OldName -Value $rename.OldName
        $record | Add-Member -MemberType NoteProperty -Name NewName -Value $rename.NewName
        $results.Add($record)
    }
    return $results.ToArray()
}

function Get-NRFirewallRuleClassification {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Snapshot,
        [Parameter(Mandatory = $true)] [object] $Desired,
        [Parameter(Mandatory = $true)] [object] $State
    )
    $configuration = Get-NRProperty $Snapshot 'configuration'
    $comparison = Get-NRProperty $Snapshot 'comparison'
    $currentValue = Get-NRProperty $configuration 'firewallRules'
    $desiredValue = Get-NRProperty $Desired 'firewallRules'
    $current = @(ConvertTo-NRObjectArray -Value $currentValue)
    $desiredItems = @(ConvertTo-NRObjectArray -Value $desiredValue)
    $persistent = Get-NRProperty $comparison 'persistentStore'
    $defaults = Get-NRProperty $comparison 'systemDefaults'
    $persistentByName = Get-NRMapByKey -Items @($persistent.Entries) -KeyProperty 'Name'
    $defaultsByName = Get-NRMapByKey -Items @($defaults.Entries) -KeyProperty 'Name'
    $currentByName = Get-NRMapByKey -Items $current -KeyProperty 'name'
    $desiredByName = Get-NRMapByKey -Items $desiredItems -KeyProperty 'name'
    $excludedNames = @(Get-NRExcludedFirewallRuleNames -Configuration $Desired)
    $excludedByName = @{}
    foreach ($name in $excludedNames) { $excludedByName[[string]$name] = $true }
    $managed = @{}
    foreach ($name in $State.managedFirewallRules) { $managed[[string]$name] = $true }
    foreach ($name in $desiredByName.Keys) { $managed[[string]$name] = $true }

    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in @(Get-NRExcludedFirewallClassifications -ExcludedNames $excludedNames -CurrentByName $currentByName)) { $results.Add($item) }
    foreach ($item in @(Get-NRManagedFirewallClassifications -DesiredByName $desiredByName -CurrentByName $currentByName -PersistentByName $persistentByName -DefaultsByName $defaultsByName)) { $results.Add($item) }
    foreach ($item in @(Get-NRRemovedManagedFirewallClassifications -ManagedNames @($State.managedFirewallRules) -DesiredByName $desiredByName -CurrentByName $currentByName -ExcludedByName $excludedByName)) { $results.Add($item) }
    foreach ($item in @(Get-NRUnmanagedFirewallClassifications -CurrentByName $currentByName -Managed $managed -PersistentByName $persistentByName -DefaultsByName $defaultsByName -ExcludedByName $excludedByName)) { $results.Add($item) }
    return @(Add-NRFirewallRuleRenameClassifications -Classifications $results.ToArray() -DesiredByName $desiredByName -CurrentByName $currentByName)
}

function Format-NRFirewallClassificationSummary {
    [CmdletBinding()]
    param([object[]] $Results, [string[]] $Order, [string] $Status)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('Firewall Rules:')
    $counts = @{}
    foreach ($item in $Results) {
        $itemStatus = [string]$item.Status
        if ($counts.ContainsKey($itemStatus)) { $counts[$itemStatus]++ }
        else { $counts[$itemStatus] = 1 }
    }
    foreach ($itemStatus in $Order) {
        $count = if ($counts.ContainsKey($itemStatus)) { [int]$counts[$itemStatus] } else { 0 }
        if ($count -gt 0 -or [string]::IsNullOrWhiteSpace($Status)) {
            $lines.Add(('  {0,-16} {1,5}' -f $itemStatus, $count))
        }
    }
    return $lines.ToArray()
}

function Format-NRFirewallClassificationItem {
    [CmdletBinding()]
    param([object] $Item)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $name = [string](Get-NRProperty $Item 'Name')
    $displayName = [string](Get-NRProperty $Item 'DisplayName')
    $status = [string](Get-NRProperty $Item 'Status')
    $defaultStatus = [string](Get-NRProperty $Item 'SystemDefaults')
    if ($status -eq 'Rename') {
        $oldName = [string](Get-NRProperty $Item 'OldName')
        $newName = [string](Get-NRProperty $Item 'NewName')
        $lines.Add(('  [Rename] {0} -> {1} (SystemDefaults: {2})' -f $oldName, $newName, $defaultStatus))
    }
    else {
        $label = if (-not [string]::IsNullOrWhiteSpace($displayName) -and $displayName -cne $name) { ' - {0}' -f $displayName } else { '' }
        $lines.Add(('  [{0}] {1}{2} (SystemDefaults: {3})' -f $status, $name, $label, $defaultStatus))
    }
    foreach ($field in @('Group', 'Program', 'Package', 'Service')) {
        $value = Get-NRProperty $Item $field
        if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value) -and [string]$value -cne 'Any') {
            $lines.Add(('      {0}: {1}' -f $field, $value))
        }
    }
    $details = Get-NRProperty $Item 'Details'
    foreach ($detail in @($details)) {
        $detailText = [string]$detail
        if (-not [string]::IsNullOrWhiteSpace($detailText)) { $lines.Add(('      ' + $detailText)) }
    }
    return $lines.ToArray()
}

function Get-NRFirewallClassificationDetailStatuses {
    [CmdletBinding()]
    param([string] $Status)
    if (-not [string]::IsNullOrWhiteSpace($Status)) { return $Status }
    return @('NewCandidate', 'ComparisonInconclusive', 'Modified', 'Rename', 'Missing', 'DeletePending', 'DeleteComplete')
}

function Test-NRFirewallClassificationItemHasDetails {
    [CmdletBinding()]
    param(
        [object] $Item,
        [string[]] $DetailStatuses,
        [bool] $IncludeExactInSync
    )
    if ([string]$Item.Status -in $DetailStatuses) { return $true }
    return ($IncludeExactInSync -and [string]$Item.Status -eq 'InSync' -and [string]$Item.SystemDefaults -eq 'ExactMatch')
}

function Add-NRFirewallClassificationLines {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[string]] $Lines,
        [object[]] $Items,
        [string] $ErrorMessage
    )
    foreach ($line in $Items) {
        if ($line -isnot [string]) { throw $ErrorMessage }
        $Lines.Add($line)
    }
}

function Format-NRFirewallRuleClassification {
    [CmdletBinding()]
    param([object[]] $Results, [string] $Status)
    $hasStatusFilter = -not [string]::IsNullOrWhiteSpace($Status)
    $detailStatuses = @(Get-NRFirewallClassificationDetailStatuses -Status $Status)
    $filtered = New-Object 'System.Collections.Generic.List[object]'
    $details = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $Results) {
        if ($hasStatusFilter -and $item.Status -ne $Status) { continue }
        $filtered.Add($item)

        $hasDetails = ([string]$item.Status -in $detailStatuses)
        if (-not $hasDetails -and -not $hasStatusFilter) {
            $hasDetails = ([string]$item.Status -eq 'InSync' -and [string]$item.SystemDefaults -eq 'ExactMatch')
        }
        if ($hasDetails) { $details.Add($item) }
    }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $order = @('NewCandidate', 'Excluded', 'ExcludedMissing', 'DefaultExcluded', 'ComparisonInconclusive', 'InSync', 'Modified', 'Rename', 'Missing', 'DeletePending', 'DeleteComplete')
    $summary = @(Format-NRFirewallClassificationSummary -Results $filtered.ToArray() -Order $order -Status $Status)
    Add-NRFirewallClassificationLines -Lines $lines -Items $summary -ErrorMessage 'Firewall classification summary renderer produced a non-string output item.'

    $sortedDetails = @($details.ToArray() | Sort-Object Status, Name)
    foreach ($item in $sortedDetails) {
        $itemLines = @(Format-NRFirewallClassificationItem -Item $item)
        Add-NRFirewallClassificationLines -Lines $lines -Items $itemLines -ErrorMessage 'Firewall classification item renderer produced a non-string output item.'
    }
    return $lines.ToArray()
}

function Add-NRFirewallRuleParameters {
    [CmdletBinding()]
    param([hashtable] $Parameters, [object] $RuleBody)
    foreach ($field in $script:NRFirewallRuleFields) {
        $value = Get-NRProperty $RuleBody $field
        if ($field -eq 'RemoteDynamicKeywordAddresses' -and $null -eq $value) { $value = @() }
        if ($null -ne $value) { $Parameters[$field] = $value }
    }
}

function Add-NRFirewallFilterParameters {
    [CmdletBinding()]
    param([hashtable] $Parameters, [object] $Filters, [string] $FilterName)
    $fields = $script:NRFirewallFilterFields[$FilterName]
    $filter = Get-NRProperty $Filters $FilterName
    foreach ($parameterName in $fields) {
        $value = Get-NRProperty $filter $parameterName
        if ($parameterName -eq 'InterfaceType' -and $null -ne $value -and $value -isnot [string]) {
            $interfaceTypes = @($value)
            if ($interfaceTypes.Count -gt 1) { throw 'Multiple InterfaceType values cannot be represented by New/Set-NetFirewallRule.' }
            if ($interfaceTypes.Count -eq 1) { $value = [string]$interfaceTypes[0] }
        }
        if ($null -ne $value) { $Parameters[$parameterName] = $value }
    }
}

function ConvertTo-NRFirewallParameters {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Record)
    $parameters = @{}
    Add-NRFirewallRuleParameters -Parameters $parameters -RuleBody (Get-NRProperty $Record 'rule')
    $filters = Get-NRProperty $Record 'filters'
    foreach ($filterName in $script:NRFirewallFilterFields.Keys) {
        Add-NRFirewallFilterParameters -Parameters $parameters -Filters $filters -FilterName $filterName
    }
    return $parameters
}

function ConvertTo-NRProfileParameters {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Record)
    $parameters = @{}
    foreach ($field in $script:NRFirewallProfileFields) {
        $value = Get-NRProperty $Record $field
        if ($null -ne $value) { $parameters[$field] = $value }
    }
    return $parameters
}

function ConvertTo-NRNrptParameters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Record,
        [switch] $ForAdd
    )
    $parameters = @{}
    $mapping = [ordered]@{
        Namespace = 'Namespace'
        IPsecTrustAuthority = 'IPsecTrustAuthority'
        DANameServers = 'DANameServers'
        DAEnable = 'DAEnable'
        DAIPsecEncryptionType = 'DAIPsecEncryptionType'
        DAIPsecRequired = 'DAIPsecRequired'
        DAProxyServerName = 'DAProxyServerName'
        DAProxyType = 'DAProxyType'
        NameServers = 'NameServers'
        NameEncoding = 'NameEncoding'
        DnsSecEnable = 'DnsSecEnable'
        DnsSecIPsecEncryptionType = 'DnsSecIPsecEncryptionType'
        DnsSecIPsecRequired = 'DnsSecIPsecRequired'
        DnsSecValidationRequired = 'DnsSecValidationRequired'
        DisplayName = 'DisplayName'
        Comment = 'Comment'
    }
    foreach ($field in $script:NRNrptFields) {
        $value = Get-NRProperty $Record $field
        if ($null -eq $value) { continue }
        if ($ForAdd -and $field -in @('DAEnable', 'DAIPsecRequired', 'DnsSecEnable', 'DnsSecIPsecRequired', 'DnsSecValidationRequired')) {
            if ([bool]$value) { $parameters[$mapping[$field]] = $true }
        }
        else { $parameters[$mapping[$field]] = $value }
    }
    return $parameters
}

function Test-NRFirewallRuleRequiresRecreation {
    [CmdletBinding()]
    param([object] $CurrentRecord, [object] $DesiredRecord)
    if (Test-NRNullTransition -Current $CurrentRecord -Desired $DesiredRecord) { return $true }
    $currentBody = Get-NRProperty $CurrentRecord 'rule'
    $desiredBody = Get-NRProperty $DesiredRecord 'rule'
    foreach ($field in @('Group', 'Platform', 'Owner')) {
        $currentValue = ConvertTo-NRCanonicalJson (Get-NRProperty $currentBody $field)
        $desiredValue = ConvertTo-NRCanonicalJson (Get-NRProperty $desiredBody $field)
        if ($currentValue -cne $desiredValue) { return $true }
    }
    return $false
}

function New-NRFirewallRule {
    [CmdletBinding()]
    param([string] $Name, [hashtable] $Parameters)
    $newParameters = @{} + $Parameters
    $newParameters['Name'] = $Name
    $newParameters['PolicyStore'] = 'PersistentStore'
    New-NetFirewallRule @newParameters -ErrorAction Stop | Out-Null
}

function Set-NRFirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [hashtable] $Parameters
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { throw 'Cannot update a Firewall rule without a Name.' }
    $setParameters = @{} + $Parameters
    if ($setParameters.ContainsKey('DisplayName')) {
        $setParameters['NewDisplayName'] = $setParameters['DisplayName']
        $setParameters.Remove('DisplayName')
    }
    $setParameters.Remove('Group')
    $setParameters.Remove('Platform')
    $setParameters.Remove('Owner')
    Set-NetFirewallRule -Name $Name -PolicyStore PersistentStore @setParameters -ErrorAction Stop | Out-Null
}

function Invoke-NRFirewallRuleReconcile {
    [CmdletBinding()]
    param(
        [string] $Name,
        [object] $DesiredRecord,
        [hashtable] $CurrentRulesByName,
        [hashtable] $CurrentSnapshotsByName
    )
    $parameters = ConvertTo-NRFirewallParameters -Record $DesiredRecord
    if (-not $CurrentRulesByName.ContainsKey($Name)) {
        New-NRFirewallRule -Name $Name -Parameters $parameters
        return
    }
    $currentSnapshot = $CurrentSnapshotsByName[$Name]
    if ((ConvertTo-NRCanonicalJson $currentSnapshot) -ceq (ConvertTo-NRCanonicalJson $DesiredRecord)) { return }
    if (Test-NRFirewallRuleRequiresRecreation -CurrentRecord $currentSnapshot -DesiredRecord $DesiredRecord) {
        Remove-NetFirewallRule -Name $Name -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop
        New-NRFirewallRule -Name $Name -Parameters $parameters
        return
    }
    Set-NRFirewallRule -Name $Name -Parameters $parameters
}

function Invoke-NRFirewallApply {
    [CmdletBinding()]
    param([object] $Desired)
    $currentRules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop)
    $currentByName = @{}
    foreach ($item in $currentRules) { $currentByName[[string]$item.Name] = $item }
    $currentSnapshots = @(Get-NRFirewallRules)
    $currentSnapshotsByName = Get-NRMapByKey -Items $currentSnapshots -KeyProperty 'name'
    $desiredRules = Get-NRMapByKey -Items (Get-NRProperty $Desired 'firewallRules') -KeyProperty 'name'

    foreach ($name in @($desiredRules.Keys | Sort-Object)) {
        Invoke-NRFirewallRuleReconcile -Name $name -DesiredRecord $desiredRules[$name] `
            -CurrentRulesByName $currentByName -CurrentSnapshotsByName $currentSnapshotsByName
    }
    Remove-NRStaleFirewallRules -CurrentRulesByName $currentByName -DesiredRules $desiredRules
}

function Remove-NRStaleFirewallRules {
    [CmdletBinding()]
    param(
        [hashtable] $CurrentRulesByName,
        [hashtable] $DesiredRules
    )
    $staleNames = @($CurrentRulesByName.Keys | Where-Object { -not $DesiredRules.ContainsKey($_) } | Sort-Object)
    foreach ($name in $staleNames) {
        Remove-NetFirewallRule -Name $name -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop
    }
}

function New-NRDynamicKeywordParameters {
    [CmdletBinding()]
    param([object] $Record)
    $parameters = @{
        Id = [string](Get-NRProperty $Record 'id')
        Keyword = [string](Get-NRProperty $Record 'Keyword')
        AutoResolve = [bool](Get-NRProperty $Record 'AutoResolve')
    }
    if (-not $parameters.AutoResolve) { $parameters['Addresses'] = [string](Get-NRProperty $Record 'Addresses') }
    return $parameters
}

function New-NRFirewallDynamicKeyword {
    [CmdletBinding()]
    param([object] $Record)
    $parameters = New-NRDynamicKeywordParameters -Record $Record
    New-NetFirewallDynamicKeywordAddress @parameters -ErrorAction Stop | Out-Null
}

function Update-NRFirewallDynamicKeyword {
    [CmdletBinding()]
    param([object] $CurrentRecord, [object] $DesiredRecord, [string] $Id)
    $oldKeyword = [string](Get-NRProperty $CurrentRecord 'Keyword')
    $newKeyword = [string](Get-NRProperty $DesiredRecord 'Keyword')
    $oldAutoResolve = [bool](Get-NRProperty $CurrentRecord 'AutoResolve')
    $newAutoResolve = [bool](Get-NRProperty $DesiredRecord 'AutoResolve')
    if ($oldKeyword -cne $newKeyword -or $oldAutoResolve -ne $newAutoResolve) {
        Remove-NetFirewallDynamicKeywordAddress -Id $Id -Confirm:$false -ErrorAction Stop
        New-NRFirewallDynamicKeyword -Record $DesiredRecord
        return
    }
    if (-not $newAutoResolve) {
        $oldAddresses = [string](Get-NRProperty $CurrentRecord 'Addresses')
        $newAddresses = [string](Get-NRProperty $DesiredRecord 'Addresses')
        if ($oldAddresses -cne $newAddresses) {
            Update-NetFirewallDynamicKeywordAddress -Id $Id -Addresses $newAddresses -Append $false -ErrorAction Stop | Out-Null
        }
    }
}

function Invoke-NRFirewallDynamicKeywordApply {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Desired,
        [switch] $RemoveStale
    )
    $currentItems = @(Get-NetFirewallDynamicKeywordAddress -All -PolicyStore PersistentStore -ErrorAction Stop)
    $currentById = @{}
    foreach ($item in $currentItems) { $currentById[[string]$item.Id] = $item }
    $desiredById = Get-NRMapByKey -Items (Get-NRProperty $Desired 'firewallDynamicKeywordAddresses') -KeyProperty 'id'

    foreach ($id in @($desiredById.Keys | Sort-Object)) {
        if (-not $currentById.ContainsKey($id)) {
            New-NRFirewallDynamicKeyword -Record $desiredById[$id]
            continue
        }
        Update-NRFirewallDynamicKeyword -CurrentRecord $currentById[$id] -DesiredRecord $desiredById[$id] -Id $id
    }
    if ($RemoveStale) {
        foreach ($id in @($currentById.Keys | Where-Object { -not $desiredById.ContainsKey($_) } | Sort-Object)) {
            Remove-NetFirewallDynamicKeywordAddress -Id $id -Confirm:$false -ErrorAction Stop
        }
    }
}

function Get-NRDynamicKeywordRecreationIds {
    [CmdletBinding()]
    param([hashtable] $CurrentById, [hashtable] $DesiredById)
    $ids = New-Object 'System.Collections.Generic.List[string]'
    foreach ($id in $DesiredById.Keys) {
        if (-not $CurrentById.ContainsKey($id)) { continue }
        $current = $CurrentById[$id]
        $desired = $DesiredById[$id]
        $keywordChanged = (Get-NRProperty $current 'Keyword') -cne (Get-NRProperty $desired 'Keyword')
        $autoResolveChanged = (Get-NRProperty $current 'AutoResolve') -ne (Get-NRProperty $desired 'AutoResolve')
        if ($keywordChanged -or $autoResolveChanged) { $ids.Add([string]$id) }
    }
    return $ids.ToArray()
}

function Test-NRFirewallRuleReferencesDynamicKeyword {
    [CmdletBinding()]
    param([object] $Record, [string[]] $DynamicKeywordIds)
    $rule = Get-NRProperty $Record 'rule'
    $references = Get-NRProperty $rule 'RemoteDynamicKeywordAddresses'
    foreach ($reference in $references) {
        if ($reference -in $DynamicKeywordIds) { return $true }
    }
    return $false
}

function Remove-NRRulesReferencingRecreatedDynamicKeywords {
    [CmdletBinding()]
    param([object] $Desired, [object] $Current)
    $currentDynamic = Get-NRMapByKey -Items (Get-NRProperty $Current 'firewallDynamicKeywordAddresses') -KeyProperty 'id'
    $desiredDynamic = Get-NRMapByKey -Items (Get-NRProperty $Desired 'firewallDynamicKeywordAddresses') -KeyProperty 'id'
    $recreateIds = @(Get-NRDynamicKeywordRecreationIds -CurrentById $currentDynamic -DesiredById $desiredDynamic)
    if ($recreateIds.Count -eq 0) { return }

    foreach ($record in (Get-NRProperty $Current 'firewallRules')) {
        if (Test-NRFirewallRuleReferencesDynamicKeyword -Record $record -DynamicKeywordIds $recreateIds) {
            Remove-NetFirewallRule -Name ([string](Get-NRProperty $record 'name')) -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop
        }
    }
}

function Invoke-NRFirewallProfileApply {
    [CmdletBinding()]
    param([object] $Desired)
    $profiles = Get-NRProperty $Desired 'firewallProfiles'
    foreach ($name in @('Domain', 'Private', 'Public')) {
        $parameters = ConvertTo-NRProfileParameters -Record (Get-NRProperty $profiles $name)
        Set-NetFirewallProfile -Name $name -PolicyStore PersistentStore @parameters -ErrorAction Stop | Out-Null
    }
}

function Get-NRNrptCurrentIndex {
    [CmdletBinding()]
    param([object[]] $Rules, [hashtable] $StateMap)
    $currentById = @{}
    $nameById = @{}
    $idByName = @{}
    foreach ($logicalId in @($StateMap.Keys)) {
        $windowsName = [string]$StateMap[$logicalId]
        if ($idByName.ContainsKey($windowsName)) {
            throw "Windows NRPT Name '$windowsName' is mapped to multiple logical ids."
        }
        $idByName[$windowsName] = [string]$logicalId
    }
    foreach ($item in $Rules) {
        $windowsName = [string](Get-NRProperty $item 'Name')
        $logicalId = if ($idByName.ContainsKey($windowsName)) { [string]$idByName[$windowsName] } else { $windowsName }
        if ($currentById.ContainsKey($logicalId)) { throw "Two NRPT rules resolve to the same logical id '$logicalId'." }
        $currentById[$logicalId] = $item
        $nameById[$logicalId] = $windowsName
    }
    return [pscustomobject]@{ CurrentById = $currentById; NameById = $nameById }
}

function Write-NRNrptState {
    [CmdletBinding()]
    param([hashtable] $StateMap, [string] $StatePath)
    $state = Read-NRStateFile -Path $StatePath
    Write-NRStateFile -Path $StatePath -State ([pscustomobject]@{ nrptRules = $StateMap; managedFirewallRules = @($state.managedFirewallRules) })
}

function Remove-NRStaleNrptRules {
    [CmdletBinding()]
    param(
        [hashtable] $CurrentById,
        [hashtable] $NameById,
        [hashtable] $DesiredRules,
        [hashtable] $StateMap,
        [string] $StatePath
    )
    foreach ($logicalId in @($CurrentById.Keys | Where-Object { -not $DesiredRules.ContainsKey($_) } | Sort-Object)) {
        Remove-DnsClientNrptRule -Name $NameById[$logicalId] -Force -ErrorAction Stop
        $CurrentById.Remove($logicalId)
        $NameById.Remove($logicalId)
        if ($StateMap.ContainsKey($logicalId)) { $StateMap.Remove($logicalId) }
        Write-NRNrptState -StateMap $StateMap -StatePath $StatePath
    }
}

function Add-NRNrptRuleAndTrack {
    [CmdletBinding()]
    param([string] $LogicalId, [object] $Record, [hashtable] $StateMap, [string] $StatePath)
    $parameters = ConvertTo-NRNrptParameters -Record $Record -ForAdd
    $created = @(Add-DnsClientNrptRule @parameters -PassThru -ErrorAction Stop)
    $windowsName = if ($created.Count -eq 1) { [string](Get-NRProperty $created[0] 'Name') } else { '' }
    if ([string]::IsNullOrWhiteSpace($windowsName)) {
        throw "Add-DnsClientNrptRule did not return the generated Windows Name for '$LogicalId'."
    }
    $StateMap[$LogicalId] = $windowsName
    Write-NRNrptState -StateMap $StateMap -StatePath $StatePath
}

function Sync-NRNrptRule {
    [CmdletBinding()]
    param(
        [string] $LogicalId,
        [object] $DesiredRecord,
        [hashtable] $CurrentById,
        [hashtable] $NameById,
        [hashtable] $StateMap,
        [string] $StatePath
    )
    if (-not $CurrentById.ContainsKey($LogicalId)) {
        Add-NRNrptRuleAndTrack -LogicalId $LogicalId -Record $DesiredRecord -StateMap $StateMap -StatePath $StatePath
        return
    }

    $currentComparable = ConvertTo-NRNrptComparable -Rule $CurrentById[$LogicalId]
    $desiredComparable = ConvertTo-NRNrptDesiredComparable -Record $DesiredRecord
    if ((ConvertTo-NRCanonicalJson $currentComparable) -ceq (ConvertTo-NRCanonicalJson $desiredComparable)) {
        $StateMap[$LogicalId] = $NameById[$LogicalId]
        return
    }

    # Recreate the NRPT rule so null, omitted, and false values are applied
    # consistently; Set-DnsClientNrptRule cannot clear every property reliably.
    Remove-DnsClientNrptRule -Name $NameById[$LogicalId] -Force -ErrorAction Stop
    Add-NRNrptRuleAndTrack -LogicalId $LogicalId -Record $DesiredRecord -StateMap $StateMap -StatePath $StatePath
}

function Invoke-NRNrptApply {
    [CmdletBinding()]
    param(
        [object] $Desired,
        [hashtable] $StateMap,
        [string] $StatePath
    )
    $currentRules = @(Get-DnsClientNrptRule -ErrorAction Stop)
    $currentIndex = Get-NRNrptCurrentIndex -Rules $currentRules -StateMap $StateMap
    $currentById = $currentIndex.CurrentById
    $nameById = $currentIndex.NameById
    $desiredRules = Get-NRMapByKey -Items (Get-NRProperty $Desired 'nrptRules') -KeyProperty 'id'

    Remove-NRStaleNrptRules -CurrentById $currentById -NameById $nameById `
        -DesiredRules $desiredRules -StateMap $StateMap -StatePath $StatePath
    foreach ($logicalId in @($desiredRules.Keys | Sort-Object)) {
        Sync-NRNrptRule -LogicalId $logicalId -DesiredRecord $desiredRules[$logicalId] `
            -CurrentById $currentById -NameById $nameById -StateMap $StateMap -StatePath $StatePath
    }
    foreach ($logicalId in @($StateMap.Keys | Where-Object { -not $desiredRules.ContainsKey($_) })) {
        $StateMap.Remove($logicalId)
    }
    Write-NRNrptState -StateMap $StateMap -StatePath $StatePath
}

function ConvertTo-NRNrptDesiredComparable {
    [CmdletBinding()]
    param([object] $Record)
    $result = [ordered]@{}
    foreach ($field in $script:NRNrptFields) { $result[$field] = Get-NRProperty $Record $field }
    return [pscustomobject]$result
}

function ConvertTo-NRNrptComparable {
    [CmdletBinding()]
    param([object] $Rule)
    $mapping = [ordered]@{
        Namespace = 'Namespace'
        IPsecTrustAuthority = 'IPsecCARestriction'
        DANameServers = 'DirectAccessDnsServers'
        DAEnable = 'DirectAccessEnabled'
        DAIPsecEncryptionType = 'DirectAccessQueryIPsecEncryption'
        DAIPsecRequired = 'DirectAccessQueryIPsecRequired'
        DAProxyServerName = 'DirectAccessProxyName'
        DAProxyType = 'DirectAccessProxyType'
        NameServers = 'NameServers'
        NameEncoding = 'NameEncoding'
        DnsSecEnable = 'DnsSecEnabled'
        DnsSecIPsecEncryptionType = 'DnsSecQueryIPsecEncryption'
        DnsSecIPsecRequired = 'DnsSecQueryIPsecRequired'
        DnsSecValidationRequired = 'DnsSecValidationRequired'
        DisplayName = 'DisplayName'
        Comment = 'Comment'
    }
    $record = [ordered]@{}
    foreach ($field in $script:NRNrptFields) { $record[$field] = Get-NRValueFromObject -Object $Rule -Name $mapping[$field] }
    return [pscustomobject]$record
}

function New-NRBackup {
    [CmdletBinding()]
    param(
        [string] $ConfigurationPath,
        [object] $CurrentState,
        [object] $State
    )
    $full = Resolve-NRFilePath -Path $ConfigurationPath
    $directory = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($full), 'backups')
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($full)
    $backupPath = [System.IO.Path]::Combine($directory, ($baseName + '.pre-apply.' + $timestamp + '.json'))
    Write-NRJsonFile -Path $backupPath -InputObject $CurrentState
    if ($null -ne $State) {
        Write-NRStateFile -Path ($backupPath -replace '\.json$', '.state.json') -State $State
    }
    return $backupPath
}

function New-NRFileBackup {
    [CmdletBinding()]
    param([string[]] $Paths, [string] $ConfigurationPath, [string] $Suffix = 'pre-change')
    $full = Resolve-NRFilePath -Path $ConfigurationPath
    $directory = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($full), 'backups')
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $copied = New-Object 'System.Collections.Generic.List[string]'
    foreach ($source in $Paths) {
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
        $extension = [System.IO.Path]::GetExtension($source)
        $sourceBaseName = [System.IO.Path]::GetFileNameWithoutExtension($source)
        $target = [System.IO.Path]::Combine($directory, ('{0}.{1}.{2}{3}' -f $sourceBaseName, $Suffix, $timestamp, $extension))
        Copy-Item -LiteralPath $source -Destination $target -ErrorAction Stop
        $copied.Add($target)
    }
    return $copied.ToArray()
}

function New-NRInitialDesiredConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Snapshot)
    return [pscustomobject][ordered]@{
        schemaVersion = $Snapshot.configuration.schemaVersion
        firewallProfiles = $Snapshot.configuration.firewallProfiles
        firewallDynamicKeywordAddresses = $Snapshot.configuration.firewallDynamicKeywordAddresses
        firewallRules = @()
        excludedFirewallRules = @()
        nrptRules = $Snapshot.configuration.nrptRules
    }
}

function Get-NRCaptureManagedFirewallRuleNames {
    [CmdletBinding()]
    param(
        [object[]] $CurrentFirewallRules,
        [object[]] $DesiredFirewallRules,
        [string[]] $PreviouslyManagedNames,
        [string[]] $ExcludedNames = @()
    )
    $currentNames = @{}
    foreach ($record in $CurrentFirewallRules) { $currentNames[[string]$record.name] = $true }
    $desiredNames = @{}
    foreach ($record in $DesiredFirewallRules) { $desiredNames[[string]$record.name] = $true }

    $excludedNameSet = @{}
    foreach ($name in $ExcludedNames) { $excludedNameSet[[string]$name] = $true }
    $managedNames = New-Object 'System.Collections.Generic.List[string]'
    $managedNameSet = @{}
    foreach ($name in @($PreviouslyManagedNames) + @($desiredNames.Keys)) {
        $key = [string]$name
        $isCurrentOrDesired = $currentNames.ContainsKey($key) -or $desiredNames.ContainsKey($key)
        if ($isCurrentOrDesired -and -not $excludedNameSet.ContainsKey($key) -and -not $managedNameSet.ContainsKey($key)) {
            $managedNameSet[$key] = $true
            $managedNames.Add($key)
        }
    }
    return $managedNames.ToArray()
}

function Update-NRCaptureManagedFirewallState {
    [CmdletBinding()]
    param(
        [string] $StatePath,
        [object] $Snapshot,
        [object] $Desired
    )
    $state = Read-NRStateFile -Path $StatePath
    $state.managedFirewallRules = @(Get-NRCaptureManagedFirewallRuleNames `
        -CurrentFirewallRules @($Snapshot.configuration.firewallRules) `
        -DesiredFirewallRules @($Desired.firewallRules) `
        -PreviouslyManagedNames @($state.managedFirewallRules) `
        -ExcludedNames @(Get-NRExcludedFirewallRuleNames -Configuration $Desired))
    Write-NRStateFile -Path $StatePath -State $state
}

function Invoke-NRCapture {
    [CmdletBinding()]
    param([string] $Path)
    $Path = Resolve-NRFilePath -Path $Path
    $snapshotPath = Get-NRSnapshotPath -Path $Path
    $statePath = Get-NRStatePath -Path $Path
    Write-Host ("[OUTPUT] Capture snapshot: {0}" -f $snapshotPath)
    Assert-NRAdministrator
    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        Write-NRStateFile -Path $statePath -State ([pscustomobject]@{ nrptRules = @{}; managedFirewallRules = @() })
    }

    $configurationExists = Test-Path -LiteralPath $Path -PathType Leaf
    if ($configurationExists) {
        $desired = Read-NRConfiguration -Path $Path
        Assert-NRConfiguration -Configuration $desired | Out-Null
    }

    $totalTimer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $snapshot = New-NRCaptureSnapshot -StatePath $statePath
        if (-not $configurationExists) {
            $desired = New-NRInitialDesiredConfiguration -Snapshot $snapshot
            Assert-NRConfiguration -Configuration $desired | Out-Null
            Write-NRJsonFile -Path $Path -InputObject $desired
        }

        Write-Progress -Id 0 -Activity 'Finalizing network capture' -Status 'Updating managed Firewall rule state...' -PercentComplete 98
        Update-NRCaptureManagedFirewallState -StatePath $statePath -Snapshot $snapshot -Desired $desired
        Write-Progress -Id 0 -Activity 'Finalizing network capture' -Status 'Serializing and writing Snapshot JSON...' -PercentComplete 99
        Write-NRJsonFile -Path $snapshotPath -InputObject $snapshot -Compress
        Write-Progress -Id 0 -Activity 'Finalizing network capture' -Status 'Capture completed.' -PercentComplete 100
        $totalTimer.Stop()
        Write-Output ("Captured snapshot: {0} ({1} PersistentStore rules, {2} SystemDefaults rules; {3:N1}s)." -f `
            $snapshotPath, @($snapshot.configuration.firewallRules).Count, $snapshot.comparison.systemDefaults.RuleCount, $totalTimer.Elapsed.TotalSeconds)
        if (-not $configurationExists) {
            Write-Output ("Initialized desired configuration: {0}. Use diff, then adopt -New to select rules." -f $Path)
        }
    }
    finally {
        if ($totalTimer.IsRunning) { $totalTimer.Stop() }
        Write-Progress -Id 0 -Activity 'Finalizing network capture' -Completed
    }
}

function Invoke-NRDiff {
    [CmdletBinding()]
    param([string] $Path, [string] $Status)
    $Path = Resolve-NRFilePath -Path $Path
    $desired = Read-NRConfiguration -Path $Path
    Assert-NRConfiguration -Configuration $desired | Out-Null
    $snapshot = Read-NRSnapshot -Path (Get-NRSnapshotPath -Path $Path)
    if ([string]$snapshot.computerName -cne [string]$env:COMPUTERNAME) {
        throw "Snapshot belongs to computer '$($snapshot.computerName)', not '$env:COMPUTERNAME'. Run capture on this computer."
    }
    $state = Read-NRStateFile -Path (Get-NRStatePath -Path $Path)

    $ruleResults = @(Get-NRFirewallRuleClassification -Snapshot $snapshot -Desired $desired -State $state)
    $firewallLines = @(Format-NRFirewallRuleClassification -Results $ruleResults -Status $Status)
    foreach ($line in $firewallLines) {
        if ($line -isnot [string]) { throw ('diff renderer returned unexpected output type: {0}' -f $line.GetType().FullName) }
        Write-Output -InputObject $line
    }

    # Profiles, Dynamic Keyword Addresses, and NRPT Rules use whole-collection
    # desired-state comparison. Firewall Rules are classified separately above.
    $otherCurrent = [pscustomobject][ordered]@{
        schemaVersion = $snapshot.configuration.schemaVersion
        firewallProfiles = $snapshot.configuration.firewallProfiles
        firewallDynamicKeywordAddresses = $snapshot.configuration.firewallDynamicKeywordAddresses
        nrptRules = $snapshot.configuration.nrptRules
    }
    $otherChanges = @(Get-NRDiff -Desired $desired -Current $otherCurrent -SkipFirewallRules)
    if (-not [string]::IsNullOrWhiteSpace($Status)) { $otherChanges = @() }
    if ($otherChanges.Count -gt 0) {
        Write-Output 'Other managed resources:'
        $otherLines = @(Format-NRDiff -Changes $otherChanges)
        foreach ($line in $otherLines) {
            if ($line -isnot [string]) { throw ('diff formatter returned unexpected output type: {0}' -f $line.GetType().FullName) }
            Write-Output -InputObject $line
        }
    }
    elseif ([string]::IsNullOrWhiteSpace($Status)) {
        Write-Output 'Other managed resources: No changes.'
    }
}

function Assert-NRAdoptArguments {
    [CmdletBinding()]
    param([bool] $New, [bool] $Update, [bool] $Rename, [string[]] $Name)
    if ($New -and ($Update -or $Rename -or $Name)) { throw 'Use -New alone, or use -Update with -Name, or -Rename with optional old -Name values. These modes cannot be combined.' }
    if ($Rename -and $Update) { throw '-Rename cannot be combined with -Update.' }
    if ($Update -and -not $Name) { throw '-Update requires -Name.' }
    if (-not $New -and -not $Update -and -not $Rename -and -not $Name) { throw 'Specify -New, -Name, or -Rename. Use -Rename to accept detected name-only replacements.' }
}

function Assert-NRAdoptNamedRule {
    [CmdletBinding()]
    param(
        [string] $Name,
        [bool] $Update,
        [hashtable] $CurrentByName,
        [hashtable] $DesiredByName,
        [hashtable] $Managed,
        [object[]] $Classifications
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { throw 'Name cannot be empty.' }
    if (-not $CurrentByName.ContainsKey($Name)) { throw "Rule '$Name' is not present in the latest capture snapshot." }
    if ($Update) {
        if (-not $DesiredByName.ContainsKey($Name) -and -not $Managed.ContainsKey($Name)) {
            throw "Rule '$Name' is not currently managed; use adopt -Name to adopt a new candidate."
        }
        return
    }
    if ($DesiredByName.ContainsKey($Name)) {
        throw "Rule '$Name' is already managed. Use -Update -Name '$Name' to adopt its current settings."
    }
    $classification = @($Classifications | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1)
    if ($classification.Count -gt 0 -and $classification[0].Status -eq 'Excluded') { return }
    if ($Managed.ContainsKey($Name)) {
        throw "Rule '$Name' is already managed. Use -Update -Name '$Name' to adopt its current settings."
    }
    if ($classification.Count -eq 0 -or $classification[0].Status -ne 'NewCandidate') {
        throw "Rule '$Name' is not a NewCandidate or an existing excluded rule. Rules exactly matching SystemDefaults are excluded from initial adoption."
    }
}

function Get-NRAdoptSelection {
    [CmdletBinding()]
    param(
        [bool] $New,
        [bool] $Update,
        [string[]] $Names,
        [object[]] $Classifications,
        [hashtable] $CurrentByName,
        [hashtable] $DesiredByName,
        [string[]] $ManagedNames
    )
    $managed = @{}
    foreach ($managedName in $ManagedNames) { $managed[[string]$managedName] = $true }
    $selected = New-Object 'System.Collections.Generic.List[string]'
    if ($New) {
        foreach ($item in $Classifications | Where-Object Status -eq 'NewCandidate') { $selected.Add([string]$item.Name) }
        return $selected.ToArray()
    }
    foreach ($itemName in $Names) {
        Assert-NRAdoptNamedRule -Name $itemName -Update $Update -CurrentByName $CurrentByName `
            -DesiredByName $DesiredByName -Managed $managed -Classifications $Classifications
        if (-not ($selected -contains $itemName)) { $selected.Add($itemName) }
    }
    return $selected.ToArray()
}
function Get-NRAdoptRenameSelection {
    [CmdletBinding()]
    param([string[]] $Names, [object[]] $Classifications)

    $renames = @($Classifications | Where-Object Status -eq 'Rename' | Sort-Object OldName, NewName)
    if ($null -eq $Names -or $Names.Count -eq 0) { return $renames }
    $selected = New-Object 'System.Collections.Generic.List[object]'
    $selectedOldNames = @{}
    foreach ($requestedName in $Names) {
        if ([string]::IsNullOrWhiteSpace($requestedName)) { throw 'Rename source Name cannot be empty.' }
        $match = @($renames | Where-Object { [string]$_.OldName -ieq $requestedName })
        if ($match.Count -eq 0) { throw "No unambiguous Rename was detected for old rule '$requestedName'. Run diff and use the old Name shown by a Rename entry." }
        if (-not $selectedOldNames.ContainsKey([string]$match[0].OldName)) {
            $selectedOldNames[[string]$match[0].OldName] = $true
            $selected.Add($match[0])
        }
    }
    return $selected.ToArray()
}

function Write-NRAdoptRenamePreview {
    [CmdletBinding()]
    param([object[]] $Renames)
    Write-Output ("Rules to rename: {0}" -f $Renames.Count)
    foreach ($rename in $Renames) {
        Write-Output ("  {0} -> {1}" -f $rename.OldName, $rename.NewName)
    }
}

function Write-NRAdoptPreview {
    [CmdletBinding()]
    param([string[]] $Names, [hashtable] $CurrentByName, [bool] $Update)
    Write-Output ("Rules to {0}: {1}" -f $(if ($Update) { 'update' } else { 'adopt' }), $Names.Count)
    foreach ($name in $Names) {
        $displayInfo = Get-NRFirewallRuleDisplayInfo -Record $CurrentByName[$name]
        $displayName = [string](Get-NRProperty $displayInfo 'DisplayName')
        $label = if (-not [string]::IsNullOrWhiteSpace($displayName) -and $displayName -cne $name) { ' - {0}' -f $displayName } else { '' }
        Write-Output ("  {0}{1}" -f $name, $label)
        foreach ($field in @('Group', 'Program', 'Package', 'Service')) {
            $value = Get-NRProperty $displayInfo $field
            if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value) -and [string]$value -cne 'Any') {
                Write-Output ('      {0}: {1}' -f $field, $value)
            }
        }
    }
}

function Update-NRAdoptedDesiredRuleRecord {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]] $Records,
        [string] $Name,
        [object] $CurrentRule
    )
    $recordFound = $false
    for ($index = 0; $index -lt $Records.Count; $index++) {
        if ([string]$Records[$index].name -ieq $Name) {
            $Records[$index] = $CurrentRule
            $recordFound = $true
        }
    }
    if (-not $recordFound) { $Records.Add($CurrentRule) }
}

function Add-NRAdoptedRule {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]] $Records,
        [object] $State,
        [string] $Name,
        [object] $CurrentRule,
        [bool] $Update
    )
    if ($Update) {
        Update-NRAdoptedDesiredRuleRecord -Records $Records -Name $Name -CurrentRule $CurrentRule
    }
    else {
        $Records.Add($CurrentRule)
    }
    if (-not ($State.managedFirewallRules -contains $Name)) {
        $State.managedFirewallRules = @($State.managedFirewallRules) + @($Name)
    }
}

function Set-NRAdoptedRenameRule {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[object]] $Records,
        [object] $State,
        [object] $Rename,
        [object] $CurrentRule
    )

    $oldName = [string]$Rename.OldName
    $newName = [string]$Rename.NewName
    $oldIndex = -1
    for ($index = 0; $index -lt $Records.Count; $index++) {
        if ([string]$Records[$index].name -ieq $oldName) {
            if ($oldIndex -ge 0) { throw "Desired State contains duplicate old Rename name '$oldName'." }
            $oldIndex = $index
        }
        elseif ([string]$Records[$index].name -ieq $newName) {
            throw "Cannot accept Rename '$oldName' -> '$newName': the new Name is already present in Desired State."
        }
    }
    if ($oldIndex -lt 0) { throw "Cannot accept Rename '$oldName' -> '$newName': the old Name is no longer in Desired State." }
    $Records[$oldIndex] = $CurrentRule

    $managedNames = New-Object 'System.Collections.Generic.List[string]'
    foreach ($managedName in @($State.managedFirewallRules)) {
        if ([string]$managedName -ine $oldName -and -not ($managedNames -contains [string]$managedName)) {
            $managedNames.Add([string]$managedName)
        }
    }
    if (-not ($managedNames -contains $newName)) { $managedNames.Add($newName) }
    $State.managedFirewallRules = @($managedNames.ToArray() | Sort-Object)
}

function Set-NRAdoptedRenameConfiguration {
    [CmdletBinding()]
    param([object] $Desired, [object] $State, [object[]] $Renames, [hashtable] $CurrentByName)

    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $Desired.firewallRules) { $records.Add($record) }
    foreach ($rename in $Renames) {
        if (-not $CurrentByName.ContainsKey([string]$rename.NewName)) {
            throw "Cannot accept Rename '$($rename.OldName)' -> '$($rename.NewName)': the new Name is no longer in the latest Snapshot."
        }
        Set-NRAdoptedRenameRule -Records $records -State $State -Rename $rename -CurrentRule $CurrentByName[[string]$rename.NewName]
    }
    $Desired.firewallRules = @($records.ToArray() | Sort-Object name)
    return [pscustomobject]@{ Desired = $Desired; State = $State }
}

function Set-NRAdoptedConfiguration {
    [CmdletBinding()]
    param([object] $Desired, [object] $State, [string[]] $Names, [hashtable] $CurrentByName, [bool] $Update)
    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($record in $Desired.firewallRules) { $records.Add($record) }
    foreach ($name in $Names) {
        Add-NRAdoptedRule -Records $records -State $State -Name $name `
            -CurrentRule $CurrentByName[$name] -Update $Update
    }
    $Desired.firewallRules = @($records.ToArray() | Sort-Object name)
    $selectedNames = @{}
    foreach ($name in $Names) { $selectedNames[[string]$name] = $true }
    $remainingExcluded = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in @(Get-NRExcludedFirewallRuleNames -Configuration $Desired)) {
        if (-not $selectedNames.ContainsKey([string]$name)) { $remainingExcluded.Add([string]$name) }
    }
    Set-NRExcludedFirewallRuleNames -Configuration $Desired -Names $remainingExcluded.ToArray() | Out-Null
    $State.managedFirewallRules = @($State.managedFirewallRules | Sort-Object -Unique)
    return [pscustomobject]@{ Desired = $Desired; State = $State }
}

function Invoke-NRAdoptRename {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [string] $Path,
        [object] $Desired,
        [object] $State,
        [object[]] $Classifications,
        [hashtable] $CurrentByName,
        [string[]] $Names
    )

    $selectedRenames = @(Get-NRAdoptRenameSelection -Names $Names -Classifications $Classifications)
    if ($selectedRenames.Count -eq 0) { Write-Output 'No unambiguous Rename candidates to adopt.'; return }
    Write-NRAdoptRenamePreview -Renames $selectedRenames
    if (-not $PSCmdlet.ShouldProcess(("{0} Firewall rule renames in {1}" -f $selectedRenames.Count, $Path), 'Accept renamed Firewall rule Names in Desired State')) { return }
    foreach ($backup in @(New-NRFileBackup -Paths @($Path, (Get-NRStatePath -Path $Path)) -ConfigurationPath $Path -Suffix 'pre-adopt')) {
        Write-Output ("Backup: {0}" -f $backup)
    }
    $updated = Set-NRAdoptedRenameConfiguration -Desired $Desired -State $State -Renames $selectedRenames -CurrentByName $CurrentByName
    Assert-NRConfiguration -Configuration $updated.Desired | Out-Null
    Write-NRJsonFile -Path $Path -InputObject $updated.Desired
    Write-NRStateFile -Path (Get-NRStatePath -Path $Path) -State $updated.State
    Write-Output ("Renamed {0} Firewall rules." -f $selectedRenames.Count)
}

function Invoke-NRAdopt {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [switch] $New,
        [switch] $Update,
        [switch] $Rename,
        [string[]] $Name
    )
    Assert-NRAdoptArguments -New $New.IsPresent -Update $Update.IsPresent -Rename $Rename.IsPresent -Name $Name
    $Path = Resolve-NRFilePath -Path $Path
    $snapshotPath = Get-NRSnapshotPath -Path $Path
    $statePath = Get-NRStatePath -Path $Path
    $desired = Read-NRConfiguration -Path $Path
    Assert-NRConfiguration -Configuration $desired | Out-Null
    $snapshot = Read-NRSnapshot -Path $snapshotPath
    if ([string]$snapshot.computerName -cne [string]$env:COMPUTERNAME) {
        throw "Snapshot belongs to computer '$($snapshot.computerName)', not '$env:COMPUTERNAME'."
    }
    $state = Read-NRStateFile -Path $statePath
    $classifications = @(Get-NRFirewallRuleClassification -Snapshot $snapshot -Desired $desired -State $state)
    $current = Get-NRMapByKey -Items @($snapshot.configuration.firewallRules) -KeyProperty 'name'
    if ($Rename) {
        $renameParameters = @{
            Path = $Path; Desired = $desired; State = $state; Classifications = $classifications
            CurrentByName = $current; Names = $Name; WhatIf = $WhatIfPreference
        }
        if ($PSBoundParameters.ContainsKey('Confirm')) { $renameParameters['Confirm'] = [bool]$PSBoundParameters['Confirm'] }
        Invoke-NRAdoptRename @renameParameters
        return
    }
    $desiredMap = Get-NRMapByKey -Items @($desired.firewallRules) -KeyProperty 'name'
    $selected = @(Get-NRAdoptSelection -New $New.IsPresent -Update $Update.IsPresent -Names $Name -Classifications $classifications -CurrentByName $current -DesiredByName $desiredMap -ManagedNames @($state.managedFirewallRules))
    if ($selected.Count -eq 0) { Write-Output 'No rules to adopt.'; return }
    Write-NRAdoptPreview -Names $selected -CurrentByName $current -Update $Update.IsPresent
    $action = if ($Update) { 'Update desired settings from capture snapshot' } else { 'Add rules to managed desired state' }
    if (-not $PSCmdlet.ShouldProcess(("{0} Firewall rules in {1}" -f $selected.Count, $Path), $action)) { return }
    foreach ($backup in @(New-NRFileBackup -Paths @($Path, $statePath) -ConfigurationPath $Path -Suffix 'pre-adopt')) {
        Write-Output ("Backup: {0}" -f $backup)
    }
    $updated = Set-NRAdoptedConfiguration -Desired $desired -State $state -Names $selected -CurrentByName $current -Update $Update.IsPresent
    Assert-NRConfiguration -Configuration $updated.Desired | Out-Null
    Write-NRJsonFile -Path $Path -InputObject $updated.Desired
    Write-NRStateFile -Path $statePath -State $updated.State
    Write-Output ("{0} {1} Firewall rules." -f $(if ($Update) { 'Updated' } else { 'Adopted' }), $selected.Count)
}

function Get-NRUnmanageKnownNameMap {
    [CmdletBinding()]
    param(
        [string[]] $DesiredNames,
        [string[]] $ManagedNames,
        [string[]] $CurrentNames,
        [string[]] $ExcludedNames
    )
    $knownNames = @{}
    foreach ($knownName in @($DesiredNames) + @($ManagedNames) + @($CurrentNames) + @($ExcludedNames)) {
        $key = [string]$knownName
        if (-not [string]::IsNullOrWhiteSpace($key) -and -not $knownNames.ContainsKey($key)) {
            $knownNames[$key] = $key
        }
    }
    return $knownNames
}

function Resolve-NRUnmanageRequestedName {
    [CmdletBinding()]
    param([string] $Name, [hashtable] $KnownNames)
    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw 'Name cannot be empty.'
    }
    if (-not $KnownNames.ContainsKey($Name)) {
        throw "Firewall rule '$Name' was not found in Desired State, managed inventory, or the latest Snapshot."
    }
    return [string]$KnownNames[$Name]
}

function Test-NRUnmanageNameRequiresAction {
    [CmdletBinding()]
    param(
        [string] $Name,
        [string[]] $DesiredNames,
        [string[]] $ManagedNames,
        [string[]] $ExcludedNames
    )
    return (($ExcludedNames -notcontains $Name) -or
        ($DesiredNames -contains $Name) -or
        ($ManagedNames -contains $Name))
}

function Get-NRUnmanageSelection {
    [CmdletBinding()]
    param(
        [string[]] $Names,
        [string[]] $DesiredNames,
        [string[]] $ManagedNames,
        [string[]] $CurrentNames = @(),
        [string[]] $ExcludedNames = @()
    )
    if ($null -eq $Names -or $Names.Count -eq 0) {
        throw 'Specify one or more -Name values to unmanage.'
    }

    $knownNames = Get-NRUnmanageKnownNameMap -DesiredNames $DesiredNames -ManagedNames $ManagedNames `
        -CurrentNames $CurrentNames -ExcludedNames $ExcludedNames
    $selected = New-Object 'System.Collections.Generic.List[string]'
    $selectedSet = @{}
    foreach ($requestedName in $Names) {
        $resolvedName = Resolve-NRUnmanageRequestedName -Name $requestedName -KnownNames $knownNames
        if (-not (Test-NRUnmanageNameRequiresAction -Name $resolvedName -DesiredNames $DesiredNames `
                -ManagedNames $ManagedNames -ExcludedNames $ExcludedNames)) {
            continue
        }
        if ($selectedSet.ContainsKey($resolvedName)) { continue }
        $selectedSet[$resolvedName] = $true
        $selected.Add($resolvedName)
    }
    return $selected.ToArray()
}

function Set-NRUnmanagedConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Desired,
        [Parameter(Mandatory = $true)] [object] $State,
        [Parameter(Mandatory = $true)] [string[]] $Names
    )
    $selected = @{}
    foreach ($name in $Names) { $selected[[string]$name] = $true }

    $Desired.firewallRules = @($Desired.firewallRules | Where-Object {
        -not $selected.ContainsKey([string]$_.name)
    })
    $State.managedFirewallRules = @($State.managedFirewallRules | Where-Object {
        -not $selected.ContainsKey([string]$_)
    })
    $excludedSet = @{}
    foreach ($name in (@(Get-NRExcludedFirewallRuleNames -Configuration $Desired) + @($Names))) {
        $key = [string]$name
        if (-not [string]::IsNullOrWhiteSpace($key)) { $excludedSet[$key] = $true }
    }
    Set-NRExcludedFirewallRuleNames -Configuration $Desired -Names @($excludedSet.Keys) | Out-Null
    return [pscustomobject]@{ Desired = $Desired; State = $State }
}

function Move-NRManagedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $SourcePath,
        [Parameter(Mandatory = $true)] [string] $DestinationPath
    )
    Move-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop | Out-Null
}

function Copy-NRManagedFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $SourcePath,
        [Parameter(Mandatory = $true)] [string] $DestinationPath
    )
    Copy-Item -LiteralPath $SourcePath -Destination $DestinationPath -Force -ErrorAction Stop | Out-Null
}

function Restore-NRUnmanageFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $ConfigurationPath,
        [Parameter(Mandatory = $true)] [string] $ConfigurationBackup,
        [Parameter(Mandatory = $true)] [string] $StatePath,
        [AllowNull()] [string] $StateBackup,
        [bool] $StateExisted
    )
    $errors = New-Object 'System.Collections.Generic.List[string]'
    try {
        Copy-NRManagedFile -SourcePath $ConfigurationBackup -DestinationPath $ConfigurationPath
    }
    catch { $errors.Add(('configuration rollback: {0}' -f $_.Exception.Message)) }

    if ($StateExisted) {
        try {
            if ([string]::IsNullOrWhiteSpace($StateBackup)) { throw 'State backup path is unavailable.' }
            Copy-NRManagedFile -SourcePath $StateBackup -DestinationPath $StatePath
        }
        catch { $errors.Add(('state rollback: {0}' -f $_.Exception.Message)) }
    }
    elseif (Test-Path -LiteralPath $StatePath -PathType Leaf) {
        try { Remove-Item -LiteralPath $StatePath -Force -ErrorAction Stop }
        catch { $errors.Add(('state cleanup: {0}' -f $_.Exception.Message)) }
    }
    return $errors.ToArray()
}

function New-NRUnmanageStagedFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $ConfigurationPath,
        [Parameter(Mandatory = $true)] [string] $StatePath,
        [Parameter(Mandatory = $true)] [object] $Updated
    )
    $token = [guid]::NewGuid().ToString('N')
    $temporaryConfigurationPath = $ConfigurationPath + '.unmanage.' + $token + '.tmp'
    $temporaryStatePath = $StatePath + '.unmanage.' + $token + '.tmp'
    try {
        # Prepare both complete files before replacing either original, so a
        # serialization failure cannot leave the pair partially updated.
        Write-NRJsonFile -Path $temporaryConfigurationPath -InputObject $Updated.Desired
        Write-NRStateFile -Path $temporaryStatePath -State $Updated.State
        return [pscustomobject]@{
            ConfigurationPath = $temporaryConfigurationPath
            StatePath = $temporaryStatePath
        }
    }
    catch {
        Remove-NRUnmanageTemporaryFiles -Paths @($temporaryConfigurationPath, $temporaryStatePath)
        throw
    }
}

function New-NRUnmanageBackupSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $ConfigurationPath,
        [Parameter(Mandatory = $true)] [string] $StatePath,
        [bool] $StateExisted
    )
    $backups = @(New-NRFileBackup -Paths @($ConfigurationPath, $StatePath) `
        -ConfigurationPath $ConfigurationPath -Suffix 'pre-unmanage')
    if ($backups.Count -lt 1) {
        throw 'Unable to create the configuration backup before unmanage.'
    }
    if ($StateExisted -and $backups.Count -lt 2) {
        throw 'Unable to create the state backup before unmanage.'
    }
    $stateBackup = $null
    if ($StateExisted) { $stateBackup = [string]$backups[1] }
    return [pscustomobject]@{
        Paths = $backups
        Configuration = [string]$backups[0]
        State = $stateBackup
    }
}

function Invoke-NRUnmanageFileCommit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $ConfigurationPath,
        [Parameter(Mandatory = $true)] [string] $TemporaryConfigurationPath,
        [Parameter(Mandatory = $true)] [string] $StatePath,
        [Parameter(Mandatory = $true)] [string] $TemporaryStatePath,
        [Parameter(Mandatory = $true)] [string] $ConfigurationBackup,
        [AllowNull()] [string] $StateBackup,
        [bool] $StateExisted
    )
    try {
        Move-NRManagedFile -SourcePath $TemporaryConfigurationPath -DestinationPath $ConfigurationPath
        Move-NRManagedFile -SourcePath $TemporaryStatePath -DestinationPath $StatePath
    }
    catch {
        $commitError = $_
        $rollbackErrors = @(Restore-NRUnmanageFiles -ConfigurationPath $ConfigurationPath `
            -ConfigurationBackup $ConfigurationBackup -StatePath $StatePath `
            -StateBackup $StateBackup -StateExisted $StateExisted)
        if ($rollbackErrors.Count -gt 0) {
            throw ("Unmanage failed: {0}. Rollback also failed: {1}. Backups are retained under the backups directory." -f `
                $commitError.Exception.Message, ($rollbackErrors -join '; '))
        }
        throw $commitError
    }
}

function Remove-NRUnmanageTemporaryFiles {
    [CmdletBinding()]
    param([string[]] $Paths)
    foreach ($temporaryPath in $Paths) {
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-NRUnmanageSnapshotNames {
    [CmdletBinding()]
    param(
        [string] $Path,
        [string[]] $Names,
        [string[]] $DesiredNames,
        [string[]] $ManagedNames,
        [string[]] $ExcludedNames
    )
    $knownNames = @{}
    foreach ($knownName in @($DesiredNames) + @($ManagedNames) + @($ExcludedNames)) {
        $key = [string]$knownName
        if (-not [string]::IsNullOrWhiteSpace($key)) { $knownNames[$key] = $true }
    }
    $needsSnapshot = @($Names | Where-Object { -not $knownNames.ContainsKey([string]$_) }).Count -gt 0
    if (-not $needsSnapshot) { return @() }

    $snapshotPath = Get-NRSnapshotPath -Path $Path
    if (-not (Test-Path -LiteralPath $snapshotPath -PathType Leaf)) { return @() }

    $snapshot = Read-NRSnapshot -Path $snapshotPath
    if ([string]$snapshot.computerName -cne [string]$env:COMPUTERNAME) {
        throw "Snapshot belongs to computer '$($snapshot.computerName)', not '$env:COMPUTERNAME'."
    }
    return @($snapshot.configuration.firewallRules | ForEach-Object { [string]$_.name })
}

function Invoke-NRUnmanage {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [string[]] $Name
    )
    $Path = Resolve-NRFilePath -Path $Path
    $statePath = Get-NRStatePath -Path $Path
    if ((Test-Path -LiteralPath $statePath) -and -not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        throw "State path exists but is not a file: $statePath"
    }
    $stateExisted = Test-Path -LiteralPath $statePath -PathType Leaf

    $desired = Read-NRConfiguration -Path $Path
    Assert-NRConfiguration -Configuration $desired | Out-Null
    $state = Read-NRStateFile -Path $statePath
    $desiredNames = @($desired.firewallRules | ForEach-Object { [string]$_.name })
    $excludedNames = @(Get-NRExcludedFirewallRuleNames -Configuration $desired)
    $currentNames = @(Get-NRUnmanageSnapshotNames -Path $Path -Names $Name `
        -DesiredNames $desiredNames -ManagedNames @($state.managedFirewallRules) -ExcludedNames $excludedNames)
    $selected = @(Get-NRUnmanageSelection -Names $Name -DesiredNames $desiredNames `
        -ManagedNames @($state.managedFirewallRules) -CurrentNames $currentNames -ExcludedNames $excludedNames)
    if ($selected.Count -eq 0) { Write-Output 'No rules to unmanage.'; return }
    $updated = Set-NRUnmanagedConfiguration -Desired $desired -State $state -Names $selected
    Assert-NRConfiguration -Configuration $updated.Desired | Out-Null

    Write-Output ("Rules to unmanage: {0}" -f $selected.Count)
    foreach ($name in $selected) { Write-Output ("  {0}" -f $name) }
    $target = "{0} Firewall rules in {1} and {2}" -f $selected.Count, $Path, $statePath
    if (-not $PSCmdlet.ShouldProcess($target, 'Exclude Firewall rules from management without changing Windows Firewall')) { return }

    $temporaryFiles = New-NRUnmanageStagedFiles -ConfigurationPath $Path -StatePath $statePath -Updated $updated
    try {
        $backups = New-NRUnmanageBackupSet -ConfigurationPath $Path -StatePath $statePath -StateExisted $stateExisted
        Invoke-NRUnmanageFileCommit -ConfigurationPath $Path `
            -TemporaryConfigurationPath $temporaryFiles.ConfigurationPath `
            -StatePath $statePath -TemporaryStatePath $temporaryFiles.StatePath `
            -ConfigurationBackup $backups.Configuration -StateBackup $backups.State `
            -StateExisted $stateExisted
        foreach ($backup in $backups.Paths) { Write-Output ("Backup: {0}" -f $backup) }
        Write-Output ("Unmanaged {0} Firewall rules. Windows Firewall settings were not changed." -f $selected.Count)
    }
    finally {
        Remove-NRUnmanageTemporaryFiles -Paths @($temporaryFiles.ConfigurationPath, $temporaryFiles.StatePath)
    }
}

function ConvertTo-NRPowerShellDictionaryLiteral {
    [CmdletBinding()]
    param([System.Collections.IDictionary] $Value)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in @($Value.Keys | Sort-Object)) {
        $keyText = ConvertTo-NRPowerShellLiteral ([string]$key)
        $valueText = ConvertTo-NRPowerShellLiteral $Value[$key]
        $parts.Add($keyText + ' = ' + $valueText)
    }
    return '@{' + [string]::Join('; ', $parts.ToArray()) + '}'
}

function ConvertTo-NRPowerShellSequenceLiteral {
    [CmdletBinding()]
    param([System.Collections.IEnumerable] $Value)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in $Value) { $parts.Add((ConvertTo-NRPowerShellLiteral $item)) }
    return '@(' + [string]::Join(', ', $parts.ToArray()) + ')'
}

function ConvertTo-NRPowerShellLiteral {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    if ($null -eq $Value) { return '$null' }
    if ($Value -is [bool]) { return $(if ($Value) { '$true' } else { '$false' }) }
    if ($Value -is [System.Enum]) { $Value = $Value.ToString() }
    if ($Value -is [string]) { return "'" + $Value.Replace("'", "''") + "'" }
    if ($Value -is [ValueType]) { return [System.Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [System.Collections.IDictionary]) { return ConvertTo-NRPowerShellDictionaryLiteral -Value $Value }
    if ($Value -is [System.Collections.IEnumerable]) { return ConvertTo-NRPowerShellSequenceLiteral -Value $Value }
    return "'" + ([string]$Value).Replace("'", "''") + "'"
}

function ConvertTo-NRPowerShellParameterText {
    [CmdletBinding()]
    param([hashtable] $Parameters)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in @($Parameters.Keys | Sort-Object)) {
        $parts.Add((' -{0} {1}' -f $key, (ConvertTo-NRPowerShellLiteral $Parameters[$key])))
    }
    return [string]::Join('', $parts.ToArray())
}

function Add-NRGeneratedScriptPreflight {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[string]] $Lines,
        [string] $Path,
        [string] $SnapshotPath,
        [string] $StatePath
    )
    $modulePath = $script:NRModulePath
    $moduleHash = (Get-FileHash -LiteralPath $modulePath -Algorithm SHA256 -ErrorAction Stop).Hash
    $configHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    $snapshotHash = (Get-FileHash -LiteralPath $SnapshotPath -Algorithm SHA256 -ErrorAction Stop).Hash
    $stateHash = (Get-FileHash -LiteralPath $StatePath -Algorithm SHA256 -ErrorAction Stop).Hash

    foreach ($line in @(
        '#requires -Version 5.1',
        '#requires -RunAsAdministrator',
        '[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = ''High'')]','param()','',
        '$ErrorActionPreference = ''Stop''',
        (' $modulePath = {0}' -f (ConvertTo-NRPowerShellLiteral $modulePath)),
        (' $expectedModuleHash = {0}' -f (ConvertTo-NRPowerShellLiteral $moduleHash)),
        'if ((Get-FileHash -LiteralPath $modulePath -Algorithm SHA256 -ErrorAction Stop).Hash -cne $expectedModuleHash) { throw ''PSNetRules module changed after generation.'' }',
        'Import-Module -Name $modulePath -Force -ErrorAction Stop',
        (' $configPath = {0}' -f (ConvertTo-NRPowerShellLiteral $Path)),
        (' $snapshotPath = {0}' -f (ConvertTo-NRPowerShellLiteral $SnapshotPath)),
        (' $statePath = {0}' -f (ConvertTo-NRPowerShellLiteral $StatePath)),
        (' $expectedConfigHash = {0}' -f (ConvertTo-NRPowerShellLiteral $configHash)),
        (' $expectedSnapshotHash = {0}' -f (ConvertTo-NRPowerShellLiteral $snapshotHash)),
        (' $expectedStateHash = {0}' -f (ConvertTo-NRPowerShellLiteral $stateHash)),
        'if ((Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash -cne $expectedConfigHash) { throw ''Desired configuration changed after generation.'' }',
        'if ((Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash -cne $expectedSnapshotHash) { throw ''Capture snapshot changed after generation.'' }',
        'if ((Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash -cne $expectedStateHash) { throw ''State file changed after generation.'' }',
        '$snapshot = Read-NRSnapshot -Path $snapshotPath',
        'if ($snapshot.computerName -cne $env:COMPUTERNAME) { throw ''Generated plan targets another computer.'' }',
        '$live = Get-NRCurrentState -StatePath $statePath',
        '$snapshotDrift = @(Get-NRDiff -Desired $snapshot.configuration -Current $live)',
        'if ($snapshotDrift.Count -gt 0) { throw (''Current system state differs from the capture snapshot ({0} differences). Run capture, diff, and generate again.'' -f $snapshotDrift.Count) }',
        '$livePersistentComparison = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore',
        '$liveDefaultsComparison = Get-NRFirewallRuleComparisonInventory -PolicyStore SystemDefaults',
        'if ((ConvertTo-NRCanonicalJson $livePersistentComparison) -cne (ConvertTo-NRCanonicalJson $snapshot.comparison.persistentStore)) { throw ''PersistentStore comparison properties changed after capture. Run capture, diff, and generate again.'' }',
        'if ((ConvertTo-NRCanonicalJson $liveDefaultsComparison) -cne (ConvertTo-NRCanonicalJson $snapshot.comparison.systemDefaults)) { throw ''SystemDefaults comparison properties changed after capture. Run capture and generate again.'' }',
        'if (-not $WhatIfPreference) { $answer = Read-Host ''Type EXECUTE GENERATED PLAN to apply these commands''; if ($answer -cne ''EXECUTE GENERATED PLAN'') { throw ''Execution cancelled.'' } }',
        'if (-not $WhatIfPreference) {',
        '    $backupDirectory = Join-Path (Split-Path -Parent $configPath) ''backups''',
        '    if (-not (Test-Path -LiteralPath $backupDirectory -PathType Container)) { New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null }',
        '    $stamp = Get-Date -Format ''yyyyMMdd-HHmmss-fff''',
        '    $backupBaseName = [System.IO.Path]::GetFileNameWithoutExtension($configPath)',
        '    Copy-Item -LiteralPath $configPath -Destination (Join-Path $backupDirectory ($backupBaseName + ''.pre-generate-execution.'' + $stamp + ''.json'')) -ErrorAction Stop',
        '    Copy-Item -LiteralPath $snapshotPath -Destination (Join-Path $backupDirectory ($backupBaseName + ''.pre-generate-execution.'' + $stamp + ''.snapshot.json'')) -ErrorAction Stop',
        '    if (Test-Path -LiteralPath $statePath -PathType Leaf) { Copy-Item -LiteralPath $statePath -Destination (Join-Path $backupDirectory ($backupBaseName + ''.pre-generate-execution.'' + $stamp + ''.state.json'')) -ErrorAction Stop }',
        '}',
        '',
        '# Firewall Rules: only rules explicitly present in the managed configuration are reconciled.'
    )) { $Lines.Add($line) }
}

function Get-NRRecreatedDynamicKeywordIds {
    [CmdletBinding()]
    param([hashtable] $CurrentDynamic, [hashtable] $DesiredDynamic)
    $ids = New-Object 'System.Collections.Generic.List[string]'
    foreach ($id in $DesiredDynamic.Keys) {
        if (-not $CurrentDynamic.ContainsKey($id)) { continue }
        $old = $CurrentDynamic[$id]
        $desired = $DesiredDynamic[$id]
        $keywordChanged = (Get-NRProperty $old 'Keyword') -cne (Get-NRProperty $desired 'Keyword')
        $resolveChanged = [bool](Get-NRProperty $old 'AutoResolve') -ne [bool](Get-NRProperty $desired 'AutoResolve')
        if ($keywordChanged -or $resolveChanged) { $ids.Add([string]$id) }
    }
    foreach ($id in $CurrentDynamic.Keys) {
        if (-not $DesiredDynamic.ContainsKey($id)) { $ids.Add([string]$id) }
    }
    return $ids.ToArray()
}

function Add-NRGeneratedDependentRuleRemovalCommands {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[string]] $Lines,
        [object[]] $FirewallRules,
        [string[]] $RecreatedIds,
        [hashtable] $ManagedNames,
        [hashtable] $DesiredRules,
        [hashtable] $ForceRecreate,
        [hashtable] $PreRemoved
    )
    foreach ($record in $FirewallRules) {
        $references = Get-NRProperty $record.rule 'RemoteDynamicKeywordAddresses'
        $matched = @($references | Where-Object { $_ -in $RecreatedIds })
        if ($matched.Count -eq 0) { continue }
        $ruleName = [string]$record.name
        if (-not $ManagedNames.ContainsKey($ruleName)) {
            throw "Cannot change a Dynamic Keyword Address referenced by unmanaged Firewall rule '$ruleName'. Adopt the rule first or leave the Dynamic Keyword Address unchanged."
        }
        $PreRemoved[$ruleName] = $true
        if ($DesiredRules.ContainsKey($ruleName)) { $ForceRecreate[$ruleName] = $true }
        $Lines.Add(("Remove-NetFirewallRule -Name {0} -PolicyStore PersistentStore -Confirm:`$false -ErrorAction Stop -WhatIf:`$WhatIfPreference" -f (ConvertTo-NRPowerShellLiteral $ruleName)))
    }
}

function Add-NRGeneratedDynamicAddressCommand {
    [CmdletBinding()]
    param([System.Collections.Generic.List[string]] $Lines, [string] $Id, [object] $Record, [object] $CurrentRecord)
    if ($null -eq $CurrentRecord) {
        $parameters = New-NRDynamicKeywordParameters -Record $Record
        $parameters['ErrorAction'] = 'Stop'
        $Lines.Add(('New-NetFirewallDynamicKeywordAddress{0} -WhatIf:$WhatIfPreference -Confirm:$false' -f (ConvertTo-NRPowerShellParameterText $parameters)))
        return
    }
    $oldKeyword = [string](Get-NRProperty $CurrentRecord 'Keyword')
    $newKeyword = [string](Get-NRProperty $Record 'Keyword')
    $oldAuto = [bool](Get-NRProperty $CurrentRecord 'AutoResolve')
    $newAuto = [bool](Get-NRProperty $Record 'AutoResolve')
    if ($oldKeyword -cne $newKeyword -or $oldAuto -ne $newAuto) {
        $Lines.Add(('Remove-NetFirewallDynamicKeywordAddress -Id {0} -Confirm:$false -ErrorAction Stop -WhatIf:$WhatIfPreference' -f (ConvertTo-NRPowerShellLiteral $Id)))
        $parameters = New-NRDynamicKeywordParameters -Record $Record
        $parameters['ErrorAction'] = 'Stop'
        $Lines.Add(('New-NetFirewallDynamicKeywordAddress{0} -WhatIf:$WhatIfPreference -Confirm:$false' -f (ConvertTo-NRPowerShellParameterText $parameters)))
        return
    }
    $oldAddresses = [string](Get-NRProperty $CurrentRecord 'Addresses')
    $newAddresses = [string](Get-NRProperty $Record 'Addresses')
    if ($newAuto -or $oldAddresses -ceq $newAddresses) { return }
    $command = 'Update-NetFirewallDynamicKeywordAddress -Id {0} -Addresses {1} -Append:$false -ErrorAction Stop' -f `
        (ConvertTo-NRPowerShellLiteral $Id), (ConvertTo-NRPowerShellLiteral $newAddresses)
    $Lines.Add(('if ($WhatIfPreference) {{ Write-Output {0} }} else {{ {1} }}' -f `
        (ConvertTo-NRPowerShellLiteral ('WHATIF: ' + $command)), $command))
}

function Add-NRGeneratedDynamicAddressCommands {
    [CmdletBinding()]
    param([System.Collections.Generic.List[string]] $Lines, [hashtable] $CurrentDynamic, [hashtable] $DesiredDynamic)
    $Lines.Add('')
    $Lines.Add('# Dynamic Keyword Addresses')
    foreach ($id in @($DesiredDynamic.Keys | Sort-Object)) {
        $currentRecord = if ($CurrentDynamic.ContainsKey($id)) { $CurrentDynamic[$id] } else { $null }
        Add-NRGeneratedDynamicAddressCommand -Lines $Lines -Id $id -Record $DesiredDynamic[$id] -CurrentRecord $currentRecord
    }
    foreach ($id in @($CurrentDynamic.Keys | Where-Object { -not $DesiredDynamic.ContainsKey($_) } | Sort-Object)) {
        $Lines.Add(('Remove-NetFirewallDynamicKeywordAddress -Id {0} -Confirm:$false -ErrorAction Stop -WhatIf:$WhatIfPreference' -f (ConvertTo-NRPowerShellLiteral $id)))
    }
}

function Add-NRGeneratedDynamicKeywordCommands {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[string]] $Lines,
        [object] $SnapshotConfiguration,
        [object] $Desired,
        [hashtable] $ManagedNames,
        [hashtable] $DesiredRules
    )
    $currentDynamic = Get-NRMapByKey -Items @($SnapshotConfiguration.firewallDynamicKeywordAddresses) -KeyProperty 'id'
    $desiredDynamic = Get-NRMapByKey -Items @($Desired.firewallDynamicKeywordAddresses) -KeyProperty 'id'
    $recreatedIds = @(Get-NRRecreatedDynamicKeywordIds -CurrentDynamic $currentDynamic -DesiredDynamic $desiredDynamic)
    $forceRecreate = @{}
    $preRemoved = @{}
    if ($recreatedIds.Count -gt 0) {
        Add-NRGeneratedDependentRuleRemovalCommands -Lines $Lines -FirewallRules @($SnapshotConfiguration.firewallRules) `
            -RecreatedIds $recreatedIds -ManagedNames $ManagedNames -DesiredRules $DesiredRules `
            -ForceRecreate $forceRecreate -PreRemoved $preRemoved
    }
    Add-NRGeneratedDynamicAddressCommands -Lines $Lines -CurrentDynamic $currentDynamic -DesiredDynamic $desiredDynamic
    return [pscustomobject]@{ ForceRecreate = $forceRecreate; PreRemoved = $preRemoved }
}

function Add-NRGeneratedFirewallRuleCommand {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[string]] $Lines,
        [string] $Name,
        [object] $DesiredRecord,
        [object] $CurrentRecord,
        [bool] $ForceRecreate,
        [bool] $PreRemoved
    )
    if ($null -eq $CurrentRecord) {
        $parameters = ConvertTo-NRFirewallParameters -Record $DesiredRecord
        $parameters['Name'] = $Name
        $parameters['PolicyStore'] = 'PersistentStore'
        $parameters['ErrorAction'] = 'Stop'
        $Lines.Add(('New-NetFirewallRule{0} -WhatIf:$WhatIfPreference -Confirm:$false' -f (ConvertTo-NRPowerShellParameterText $parameters)))
        return
    }
    $differs = (ConvertTo-NRCanonicalJson $CurrentRecord) -cne (ConvertTo-NRCanonicalJson $DesiredRecord)
    if (-not $differs -and -not $ForceRecreate) { return }
    $recreate = $ForceRecreate -or (Test-NRFirewallRuleRequiresRecreation -CurrentRecord $CurrentRecord -DesiredRecord $DesiredRecord)
    if ($recreate) {
        if (-not $PreRemoved) {
            $Lines.Add(('Remove-NetFirewallRule -Name {0} -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop -WhatIf:$WhatIfPreference' -f (ConvertTo-NRPowerShellLiteral $Name)))
        }
        $parameters = ConvertTo-NRFirewallParameters -Record $DesiredRecord
        $parameters['Name'] = $Name
        $parameters['PolicyStore'] = 'PersistentStore'
        $parameters['ErrorAction'] = 'Stop'
        $Lines.Add(('New-NetFirewallRule{0} -WhatIf:$WhatIfPreference -Confirm:$false' -f (ConvertTo-NRPowerShellParameterText $parameters)))
        return
    }
    $parameters = ConvertTo-NRFirewallParameters -Record $DesiredRecord
    if ($parameters.ContainsKey('DisplayName')) {
        $parameters['NewDisplayName'] = $parameters['DisplayName']
        $parameters.Remove('DisplayName')
    }
    foreach ($field in @('Group', 'Platform', 'Owner')) { $parameters.Remove($field) }
    $parameters['Name'] = $Name
    $parameters['PolicyStore'] = 'PersistentStore'
    $parameters['ErrorAction'] = 'Stop'
    $Lines.Add(('Set-NetFirewallRule{0} -WhatIf:$WhatIfPreference -Confirm:$false' -f (ConvertTo-NRPowerShellParameterText $parameters)))
}

function Add-NRGeneratedFirewallRuleCommands {
    [CmdletBinding()]
    param(
        [System.Collections.Generic.List[string]] $Lines,
        [hashtable] $CurrentRules,
        [hashtable] $DesiredRules,
        [string[]] $ManagedNames,
        [hashtable] $ForceRecreate,
        [hashtable] $PreRemoved
    )
    $Lines.Add('')
    $Lines.Add('# Firewall Rule create/update/recreate')
    foreach ($name in @($DesiredRules.Keys | Sort-Object)) {
        $currentRecord = if ($CurrentRules.ContainsKey($name)) { $CurrentRules[$name] } else { $null }
        Add-NRGeneratedFirewallRuleCommand -Lines $Lines -Name $name -DesiredRecord $DesiredRules[$name] `
            -CurrentRecord $currentRecord -ForceRecreate $ForceRecreate.ContainsKey($name) -PreRemoved $PreRemoved.ContainsKey($name)
    }
    foreach ($name in $ManagedNames) {
        $key = [string]$name
        if ($DesiredRules.ContainsKey($key) -or -not $CurrentRules.ContainsKey($key) -or $PreRemoved.ContainsKey($key)) { continue }
        $Lines.Add(('Remove-NetFirewallRule -Name {0} -PolicyStore PersistentStore -Confirm:$false -ErrorAction Stop -WhatIf:$WhatIfPreference' -f (ConvertTo-NRPowerShellLiteral $key)))
    }
}

function Add-NRGeneratedFirewallProfileCommands {
    [CmdletBinding()]
    param([System.Collections.Generic.List[string]] $Lines, [object] $Desired, [object] $SnapshotConfiguration)
    $Lines.Add('')
    $Lines.Add('# Firewall Profiles')
    foreach ($profileName in @('Domain', 'Private', 'Public')) {
        $desiredProfile = Get-NRProperty $Desired.firewallProfiles $profileName
        $currentProfile = Get-NRProperty $SnapshotConfiguration.firewallProfiles $profileName
        if (@(Get-NRObjectChanges -Before $currentProfile -After $desiredProfile).Count -eq 0) { continue }
        $parameters = ConvertTo-NRProfileParameters -Record $desiredProfile
        $parameters['Name'] = $profileName
        $parameters['PolicyStore'] = 'PersistentStore'
        $parameters['ErrorAction'] = 'Stop'
        $Lines.Add(('Set-NetFirewallProfile{0} -WhatIf:$WhatIfPreference -Confirm:$false' -f (ConvertTo-NRPowerShellParameterText $parameters)))
    }
}

function Add-NRGeneratedNrptRemovalCommands {
    [CmdletBinding()]
    param([System.Collections.Generic.List[string]] $Lines, [hashtable] $CurrentNrpt, [hashtable] $DesiredNrpt)
    foreach ($id in @($CurrentNrpt.Keys | Where-Object { -not $DesiredNrpt.ContainsKey($_) } | Sort-Object)) {
        $idText = ConvertTo-NRPowerShellLiteral $id
        $Lines.Add((' $windowsName = if ($state.nrptRules.ContainsKey({0})) {{ [string]$state.nrptRules[{0}] }} else {{ {0} }}' -f $idText))
        $Lines.Add('Remove-DnsClientNrptRule -Name $windowsName -Force -ErrorAction Stop -WhatIf:$WhatIfPreference -Confirm:$false')
        $Lines.Add(('if (-not $WhatIfPreference -and $state.nrptRules.ContainsKey({0})) {{ $state.nrptRules.Remove({0}); Write-NRStateFile -Path $statePath -State $state }}' -f $idText))
    }
}

function Add-NRGeneratedNrptDesiredCommands {
    [CmdletBinding()]
    param([System.Collections.Generic.List[string]] $Lines, [hashtable] $CurrentNrpt, [hashtable] $DesiredNrpt)
    foreach ($id in @($DesiredNrpt.Keys | Sort-Object)) {
        $record = $DesiredNrpt[$id]
        $needsAdd = -not $CurrentNrpt.ContainsKey($id)
        $needsUpdate = $false
        if (-not $needsAdd) { $needsUpdate = (ConvertTo-NRCanonicalJson $CurrentNrpt[$id]) -cne (ConvertTo-NRCanonicalJson $record) }
        if (-not $needsAdd -and -not $needsUpdate) { continue }
        if ($needsUpdate) {
            $idText = ConvertTo-NRPowerShellLiteral $id
            $Lines.Add((' $windowsName = if ($state.nrptRules.ContainsKey({0})) {{ [string]$state.nrptRules[{0}] }} else {{ {0} }}' -f $idText))
            $Lines.Add('Remove-DnsClientNrptRule -Name $windowsName -Force -ErrorAction Stop -WhatIf:$WhatIfPreference -Confirm:$false')
            $Lines.Add(('if (-not $WhatIfPreference -and $state.nrptRules.ContainsKey({0})) {{ $state.nrptRules.Remove({0}); Write-NRStateFile -Path $statePath -State $state }}' -f $idText))
        }
        $parameters = ConvertTo-NRNrptParameters -Record $record -ForAdd
        $parameters['PassThru'] = $true
        $parameters['ErrorAction'] = 'Stop'
        $parameterText = ConvertTo-NRPowerShellParameterText $parameters
        $errorText = ConvertTo-NRPowerShellLiteral ("Add-DnsClientNrptRule did not return a Windows Name for '$id'.")
        $idText = ConvertTo-NRPowerShellLiteral $id
        $Lines.Add(('if (-not $WhatIfPreference) {{ $created = @(Add-DnsClientNrptRule{0}); if ($created.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$created[0].Name)) {{ throw {1} }}; $state.nrptRules[{2}] = [string]$created[0].Name; Write-NRStateFile -Path $statePath -State $state }} else {{ Add-DnsClientNrptRule{0} -WhatIf:$true -Confirm:$false | Out-Null }}' -f $parameterText, $errorText, $idText))
    }
}

function Add-NRGeneratedNrptCommands {
    [CmdletBinding()]
    param([System.Collections.Generic.List[string]] $Lines, [object] $Desired, [object] $SnapshotConfiguration)
    $currentNrpt = Get-NRMapByKey -Items @($SnapshotConfiguration.nrptRules) -KeyProperty 'id'
    $desiredNrpt = Get-NRMapByKey -Items @($Desired.nrptRules) -KeyProperty 'id'
    $Lines.Add('')
    $Lines.Add('# Local NRPT Rules')
    $Lines.Add('$state = Read-NRStateFile -Path $statePath')
    Add-NRGeneratedNrptRemovalCommands -Lines $Lines -CurrentNrpt $currentNrpt -DesiredNrpt $desiredNrpt
    Add-NRGeneratedNrptDesiredCommands -Lines $Lines -CurrentNrpt $currentNrpt -DesiredNrpt $desiredNrpt
    $Lines.Add('if (-not $WhatIfPreference) { Write-NRStateFile -Path $statePath -State $state }')
}

function Write-NRGeneratedScript {
    [CmdletBinding()]
    param([string] $OutputPath, [System.Collections.Generic.List[string]] $Lines)
    $encoding = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($OutputPath, ([string]::Join([Environment]::NewLine, $Lines.ToArray()) + [Environment]::NewLine), $encoding)
}

function Invoke-NRGenerate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [string] $OutputPath,
        [switch] $Force
    )
    $Path = Resolve-NRFilePath -Path $Path
    $snapshotPath = Get-NRSnapshotPath -Path $Path
    $statePath = Get-NRStatePath -Path $Path
    $desired = Read-NRConfiguration -Path $Path
    Assert-NRConfiguration -Configuration $desired | Out-Null
    $snapshot = Read-NRSnapshot -Path $snapshotPath
    if ([string]$snapshot.computerName -cne [string]$env:COMPUTERNAME) {
        throw "Snapshot belongs to computer '$($snapshot.computerName)', not '$env:COMPUTERNAME'."
    }
    $state = Read-NRStateFile -Path $statePath
    $snapshotConfiguration = $snapshot.configuration
    $currentRules = Get-NRMapByKey -Items @($snapshotConfiguration.firewallRules) -KeyProperty 'name'
    $desiredRules = Get-NRMapByKey -Items @($desired.firewallRules) -KeyProperty 'name'
    $managedNames = @{}
    foreach ($name in @($state.managedFirewallRules) + @($desiredRules.Keys)) { $managedNames[[string]$name] = $true }
    foreach ($name in @(Get-NRExcludedFirewallRuleNames -Configuration $desired)) { $managedNames.Remove([string]$name) }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    Add-NRGeneratedScriptPreflight -Lines $lines -Path $Path -SnapshotPath $snapshotPath -StatePath $statePath
    $dynamicPlan = Add-NRGeneratedDynamicKeywordCommands -Lines $lines -SnapshotConfiguration $snapshotConfiguration -Desired $desired -ManagedNames $managedNames -DesiredRules $desiredRules
    Add-NRGeneratedFirewallRuleCommands -Lines $lines -CurrentRules $currentRules -DesiredRules $desiredRules `
        -ManagedNames @($managedNames.Keys) -ForceRecreate $dynamicPlan.ForceRecreate -PreRemoved $dynamicPlan.PreRemoved
    Add-NRGeneratedFirewallProfileCommands -Lines $lines -Desired $desired -SnapshotConfiguration $snapshotConfiguration
    Add-NRGeneratedNrptCommands -Lines $lines -Desired $desired -SnapshotConfiguration $snapshotConfiguration
    $lines.Add('')
    $lines.Add('if ($WhatIfPreference) { Write-Output ''WhatIf preview completed; no changes were applied.'' } else { Write-Output ''Generated commands completed. Run capture, then diff, to verify the resulting state.'' }')

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $directory = [System.IO.Path]::GetDirectoryName($Path)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $OutputPath = [System.IO.Path]::Combine($directory, ($baseName + '.generate.ps1'))
    }
    $OutputPath = Resolve-NRFilePath -Path $OutputPath
    $outputDirectory = [System.IO.Path]::GetDirectoryName($OutputPath)
    if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) { throw "Output directory does not exist: $outputDirectory" }
    if ((Test-Path -LiteralPath $OutputPath -PathType Leaf) -and -not $Force) {
        throw "Generated script already exists: $OutputPath. Use -Force to overwrite it."
    }
    if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Write generated PowerShell apply script')) { return }
    Write-NRGeneratedScript -OutputPath $OutputPath -Lines $lines
    Write-Output ("Generated: {0}" -f $OutputPath)
    Write-Output 'Review the generated commands. Execute the script in an elevated PowerShell 5.1 session, then run capture and diff.'
}

function Invoke-NRValidate {
    [CmdletBinding()]
    param([string] $Path)
    $Path = Resolve-NRFilePath -Path $Path
    $configuration = Read-NRConfiguration -Path $Path
    Assert-NRConfiguration -Configuration $configuration | Out-Null
    Write-Output 'Configuration is valid.'
}

Export-ModuleMember -Function @(
    'Resolve-NRFilePath', 'Get-NRProperty', 'Test-NRProperty', 'Test-NRObjectLike', 'Get-NRPropertyNames', 'Get-NRCanonicalValue', 'ConvertTo-NRCanonicalJson',
    'Get-NRCanonicalDictionary', 'Get-NRCanonicalSequence', 'Get-NRCanonicalObject', 'Get-NRPropertyChange',
    'Test-NRNumberValue', 'Test-NRScalarValue', 'Test-NRStringArrayValue', 'Test-NRStringOrArrayValue', 'Test-NRFieldValue',
    'Assert-NRArrayField', 'Assert-NRFirewallProfile', 'Assert-NRFirewallProfiles', 'Assert-NRDynamicKeywordAddress',
    'Assert-NRFirewallDynamicKeywordAddresses', 'Assert-NRFirewallRuleBody', 'Assert-NRFirewallFilter', 'Assert-NRFirewallRule',
    'Assert-NRFirewallRules', 'Assert-NRNrptRule', 'Assert-NRNrptRules', 'Get-NRKeyedCollectionDiff', 'Get-NRProfileDiff',
    'New-NRChangeRecord', 'Add-NRFirewallRuleParameters', 'Add-NRFirewallFilterParameters', 'Test-NRFirewallRuleRequiresRecreation',
    'New-NRFirewallRule', 'Set-NRFirewallRule', 'Invoke-NRFirewallRuleReconcile', 'Remove-NRStaleFirewallRules', 'New-NRDynamicKeywordParameters',
    'New-NRFirewallDynamicKeyword', 'Update-NRFirewallDynamicKeyword', 'Get-NRNrptCurrentIndex', 'Write-NRNrptState',
    'Remove-NRStaleNrptRules', 'Add-NRNrptRuleAndTrack', 'Sync-NRNrptRule',
    'Get-NRObjectChanges', 'Get-NRDiff', 'Format-NRDiff', 'Get-NRStatePath', 'Read-NRStateFile',
    'Write-NRStateFile', 'Write-NRJsonFile', 'Read-NRConfiguration', 'Assert-NRObjectShape', 'Assert-NRFieldType', 'Assert-NRConfiguration',
    'Test-NRIsAdministrator', 'Assert-NRAdministrator', 'Get-NRStringArrayFromObject', 'Get-NRFirewallFilterSpecs', 'Get-NRFirewallFilterIndex', 'Get-NRFirewallFilterFromIndex', 'Get-NRFirewallFilter', 'Get-NRFirewallRules', 'Get-NRFirewallDynamicKeywordAddresses', 'Get-NRFirewallProfiles',
    'Get-NRNrptRules', 'Get-NRCurrentState', 'ConvertTo-NRFirewallParameters', 'ConvertTo-NRProfileParameters',
    'ConvertTo-NRNrptParameters', 'ConvertTo-NRNrptComparable', 'ConvertTo-NRNrptDesiredComparable', 'New-NRBackup',
    'Invoke-NRFirewallApply', 'Invoke-NRFirewallDynamicKeywordApply', 'Remove-NRRulesReferencingRecreatedDynamicKeywords', 'Invoke-NRFirewallProfileApply', 'Invoke-NRNrptApply',
    'Get-NRSnapshotPath', 'Read-NRSnapshot', 'Get-NRFirewallRuleComparisonInventory', 'Get-NRDefaultRuleStatus', 'New-NRCaptureSnapshot', 'Get-NRFirewallRuleClassification', 'Format-NRFirewallRuleClassification',
    'New-NRFileBackup', 'Invoke-NRCapture', 'Invoke-NRDiff', 'Invoke-NRAdopt', 'Get-NRUnmanageSelection', 'Set-NRUnmanagedConfiguration', 'Restore-NRUnmanageFiles', 'Invoke-NRUnmanage', 'ConvertTo-NRPowerShellLiteral', 'ConvertTo-NRPowerShellParameterText', 'Invoke-NRGenerate', 'Invoke-NRValidate'
)
