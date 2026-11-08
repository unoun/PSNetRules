# Shared typed fixtures for Unit, Windows Contract, and Integration tests.
# Builders provide consistent PSCustomObject shapes for mocked cmdlet output,
# desired-state records, and projections of native Windows objects.

function New-NRFixtureObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary] $Properties
    )

    $orderedProperties = [ordered]@{}
    foreach ($key in $Properties.Keys) {
        $orderedProperties[[string]$key] = $Properties[$key]
    }
    return [pscustomobject]$orderedProperties
}

function New-NRFixtureObjectFromNative {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $InputObject,
        [Parameter(Mandatory = $true)] [string[]] $PropertyNames
    )

    $properties = [ordered]@{}
    $cimProperties = $null
    try { $cimProperties = $InputObject.CimInstanceProperties } catch { }
    foreach ($propertyName in $PropertyNames) {
        $member = $InputObject.PSObject.Properties[$propertyName]
        if ($null -ne $member) {
            $properties[$propertyName] = $member.Value
            continue
        }

        # Some CIM properties are exposed only through CimInstanceProperties.
        if ($null -ne $cimProperties) {
            $cimMember = $cimProperties[$propertyName]
            if ($null -ne $cimMember) {
                $properties[$propertyName] = $cimMember.Value
            }
        }
    }
    return New-NRFixtureObject -Properties $properties
}

function New-NRFixtureFirewallProfile {
    [CmdletBinding()]
    param(
        [string] $Name,
        [object] $InputObject,
        [System.Collections.IDictionary] $Properties
    )

    $fieldNames = @(
        'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction', 'AllowInboundRules',
        'AllowLocalFirewallRules', 'AllowLocalIPsecRules', 'AllowUserApps', 'AllowUserPorts',
        'AllowUnicastResponseToMulticast', 'NotifyOnListen', 'EnableStealthModeForIPsec',
        'LogFileName', 'LogMaxSizeKilobytes', 'LogAllowed', 'LogBlocked', 'LogIgnored',
        'DisabledInterfaceAliases'
    )
    if ($PSBoundParameters.ContainsKey('InputObject')) {
        $copyNames = @()
        if (Test-NRFixtureHasProperty -InputObject $InputObject -Name 'Name') { $copyNames += 'Name' }
        $copyNames += $fieldNames
        $fixture = New-NRFixtureObjectFromNative -InputObject $InputObject -PropertyNames $copyNames
        if ($PSBoundParameters.ContainsKey('Name')) { $fixture.Name = $Name }
        return $fixture
    }

    $values = [ordered]@{
        Enabled = 'True'
        DefaultInboundAction = 'Block'
        DefaultOutboundAction = 'Allow'
        AllowInboundRules = 'True'
        AllowLocalFirewallRules = 'True'
        AllowLocalIPsecRules = 'True'
        AllowUserApps = 'True'
        AllowUserPorts = 'True'
        AllowUnicastResponseToMulticast = 'True'
        NotifyOnListen = 'True'
        EnableStealthModeForIPsec = 'True'
        LogFileName = 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log'
        LogMaxSizeKilobytes = 4096
        LogAllowed = 'False'
        LogBlocked = 'False'
        LogIgnored = 'False'
        DisabledInterfaceAliases = @()
    }
    if ($PSBoundParameters.ContainsKey('Name')) { $values.Name = $Name }
    if ($PSBoundParameters.ContainsKey('Properties')) {
        foreach ($key in $Properties.Keys) { $values[[string]$key] = $Properties[$key] }
    }
    return New-NRFixtureObject -Properties $values
}

function Test-NRFixtureHasProperty {
    [CmdletBinding()]
    param([object] $InputObject, [string] $Name)

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) {
        return $InputObject.Contains($Name)
    }
    if ($null -ne $InputObject.PSObject.Properties[$Name]) { return $true }

    $cimProperties = $null
    try { $cimProperties = $InputObject.CimInstanceProperties } catch { }
    if ($null -ne $cimProperties) { return ($null -ne $cimProperties[$Name]) }
    return $false
}

function New-NRFixtureFirewallRuleRecord {
    [CmdletBinding()]
    param(
        [string] $Name = 'AllowHttps',
        [string] $DisplayName,
        [string] $Description = '',
        [AllowNull()] [string] $Group = '',
        [string] $Enabled = 'True',
        [string] $LocalPort = '443'
    )

    if (-not $PSBoundParameters.ContainsKey('DisplayName')) { $DisplayName = $Name }
    return [pscustomobject][ordered]@{
        name = $Name
        rule = [pscustomobject][ordered]@{
            name = $Name
            DisplayName = $DisplayName
            Description = $Description
            Group = $Group
            Enabled = $Enabled
            Profile = @('Private')
            Platform = @()
            Direction = 'Inbound'
            Action = 'Allow'
            EdgeTraversalPolicy = 'Block'
            LooseSourceMapping = $false
            LocalOnlyMapping = $false
            Owner = $null
            RemoteDynamicKeywordAddresses = @()
        }
        filters = [pscustomobject][ordered]@{
            address = [pscustomobject]@{ LocalAddress = @('Any'); RemoteAddress = @('Any') }
            port = [pscustomobject]@{ Protocol = 'TCP'; LocalPort = @($LocalPort); RemotePort = @('Any'); IcmpType = @(); DynamicTarget = 'Any' }
            application = [pscustomobject]@{ Program = 'Any'; Package = 'Any' }
            service = [pscustomobject]@{ Service = 'Any' }
            interface = [pscustomobject]@{ InterfaceAlias = @('Any') }
            interfaceType = [pscustomobject]@{ InterfaceType = @('Any') }
            security = [pscustomobject]@{ LocalUser = 'Any'; RemoteUser = 'Any'; RemoteMachine = 'Any'; Authentication = 'NotRequired'; Encryption = 'NotRequired'; OverrideBlockRules = $false }
        }
    }
}

function New-NRFixtureFirewallRuleObject {
    [CmdletBinding()]
    param(
        [object] $InputObject,
        [System.Collections.IDictionary] $Properties
    )

    $fieldNames = @(
        'Name', 'InstanceID', 'DisplayName', 'Description', 'Group', 'Enabled', 'Profile', 'Platform',
        'Direction', 'Action', 'EdgeTraversalPolicy', 'LooseSourceMapping', 'LocalOnlyMapping',
        'Owner', 'RemoteDynamicKeywordAddresses'
    )
    if ($PSBoundParameters.ContainsKey('InputObject')) {
        return New-NRFixtureObjectFromNative -InputObject $InputObject -PropertyNames $fieldNames
    }

    $values = [ordered]@{
        Name = 'FixtureFirewallRule'
        InstanceID = 'fixture-firewall-rule-id'
        DisplayName = 'Fixture Firewall Rule'
        Description = ''
        Group = ''
        Enabled = 'True'
        Profile = @('Private')
        Platform = @()
        Direction = 'Inbound'
        Action = 'Allow'
        EdgeTraversalPolicy = 'Block'
        LooseSourceMapping = $false
        LocalOnlyMapping = $false
        Owner = $null
        RemoteDynamicKeywordAddresses = @()
    }
    if ($PSBoundParameters.ContainsKey('Properties')) {
        foreach ($key in $Properties.Keys) { $values[[string]$key] = $Properties[$key] }
    }
    return New-NRFixtureObject -Properties $values
}

function New-NRFixtureFirewallFilter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Address', 'Application', 'Port', 'Service', 'Interface', 'InterfaceType', 'Security')]
        [string] $Type,
        [object] $InputObject,
        [System.Collections.IDictionary] $Properties,
        [string] $InstanceId = 'fixture-firewall-rule-id'
    )

    $fieldNames = switch ($Type) {
        'Address' { @('InstanceID', 'LocalAddress', 'RemoteAddress') }
        'Application' { @('InstanceID', 'Program', 'Package') }
        'Port' { @('InstanceID', 'Protocol', 'LocalPort', 'RemotePort', 'IcmpType', 'DynamicTarget') }
        'Service' { @('InstanceID', 'Service') }
        'Interface' { @('InstanceID', 'InterfaceAlias') }
        'InterfaceType' { @('InstanceID', 'InterfaceType') }
        'Security' { @('InstanceID', 'LocalUser', 'RemoteUser', 'RemoteMachine', 'Authentication', 'Encryption', 'OverrideBlockRules') }
    }
    if ($PSBoundParameters.ContainsKey('InputObject')) {
        return New-NRFixtureObjectFromNative -InputObject $InputObject -PropertyNames $fieldNames
    }

    $values = [ordered]@{ InstanceID = $InstanceId }
    switch ($Type) {
        'Address' { $values.LocalAddress = @('Any'); $values.RemoteAddress = @('Any') }
        'Application' { $values.Program = 'Any'; $values.Package = 'Any' }
        'Port' { $values.Protocol = 'TCP'; $values.LocalPort = @('443'); $values.RemotePort = @('Any'); $values.IcmpType = @(); $values.DynamicTarget = 'Any' }
        'Service' { $values.Service = 'Any' }
        'Interface' { $values.InterfaceAlias = @('Any') }
        'InterfaceType' { $values.InterfaceType = @('Any') }
        'Security' { $values.LocalUser = 'Any'; $values.RemoteUser = 'Any'; $values.RemoteMachine = 'Any'; $values.Authentication = 'NotRequired'; $values.Encryption = 'NotRequired'; $values.OverrideBlockRules = $false }
    }
    if ($PSBoundParameters.ContainsKey('Properties')) {
        foreach ($key in $Properties.Keys) { $values[[string]$key] = $Properties[$key] }
    }
    return New-NRFixtureObject -Properties $values
}

function New-NRFixtureNrptRuleRecord {
    [CmdletBinding()]
    param(
        [string] $Id = 'corp-dns',
        [string[]] $Namespace = @('.corp.example'),
        [string] $Server = '10.10.0.53',
        [string] $DisplayName = 'Corporate DNS',
        [string] $Comment = ''
    )

    return [pscustomobject][ordered]@{
        id = $Id
        Namespace = @($Namespace)
        IPsecTrustAuthority = $null
        DANameServers = @()
        DAEnable = $false
        DAIPsecEncryptionType = $null
        DAIPsecRequired = $false
        DAProxyServerName = $null
        DAProxyType = $null
        NameServers = @($Server)
        NameEncoding = 'Punycode'
        DnsSecEnable = $false
        DnsSecIPsecEncryptionType = $null
        DnsSecIPsecRequired = $false
        DnsSecValidationRequired = $false
        DisplayName = $DisplayName
        Comment = $Comment
    }
}

function New-NRFixtureNrptWindowsRule {
    [CmdletBinding()]
    param(
        [object] $InputObject,
        [System.Collections.IDictionary] $Properties
    )

    $fieldNames = @(
        'Name', 'Namespace', 'IPsecCARestriction', 'DirectAccessDnsServers', 'DirectAccessEnabled',
        'DirectAccessQueryIPsecEncryption', 'DirectAccessQueryIPsecRequired', 'DirectAccessProxyName',
        'DirectAccessProxyType', 'NameServers', 'NameEncoding', 'DnsSecEnabled',
        'DnsSecQueryIPsecEncryption', 'DnsSecQueryIPsecRequired', 'DnsSecValidationRequired',
        'DisplayName', 'Comment'
    )
    if ($PSBoundParameters.ContainsKey('InputObject')) {
        return New-NRFixtureObjectFromNative -InputObject $InputObject -PropertyNames $fieldNames
    }

    $values = [ordered]@{
        Name = '{11111111-1111-1111-1111-111111111111}'
        Namespace = @('.unit.example')
        IPsecCARestriction = $null
        DirectAccessDnsServers = @()
        DirectAccessEnabled = $false
        DirectAccessQueryIPsecEncryption = $null
        DirectAccessQueryIPsecRequired = $false
        DirectAccessProxyName = $null
        DirectAccessProxyType = $null
        NameServers = @('192.0.2.1')
        NameEncoding = 'Punycode'
        DnsSecEnabled = $false
        DnsSecQueryIPsecEncryption = $null
        DnsSecQueryIPsecRequired = $false
        DnsSecValidationRequired = $false
        DisplayName = 'Unit NRPT'
        Comment = 'fixture'
    }
    if ($PSBoundParameters.ContainsKey('Properties')) {
        foreach ($key in $Properties.Keys) { $values[[string]$key] = $Properties[$key] }
    }
    return New-NRFixtureObject -Properties $values
}

function New-NRFixtureDynamicKeywordAddress {
    [CmdletBinding()]
    param(
        [object] $InputObject,
        [System.Collections.IDictionary] $Properties
    )

    $fieldNames = @('Id', 'Keyword', 'Addresses', 'AutoResolve')
    if ($PSBoundParameters.ContainsKey('InputObject')) {
        return New-NRFixtureObjectFromNative -InputObject $InputObject -PropertyNames $fieldNames
    }

    $values = [ordered]@{
        Id = '{11111111-1111-1111-1111-111111111111}'
        Keyword = 'Static'
        Addresses = '192.0.2.10'
        AutoResolve = $false
    }
    if ($PSBoundParameters.ContainsKey('Properties')) {
        foreach ($key in $Properties.Keys) { $values[[string]$key] = $Properties[$key] }
    }
    return New-NRFixtureObject -Properties $values
}

function New-NRFixtureCimFirewallRule {
    [CmdletBinding()]
    param([string] $Name = 'Rule-A', [string] $InstanceId = 'rule-a-id')

    return New-CimInstance -Namespace 'root/standardcimv2' -ClassName 'MSFT_NetFirewallRule' `
        -ClientOnly -Property @{ Name = $Name; InstanceID = $InstanceId }
}

function New-NRFixtureConfiguration {
    [CmdletBinding()]
    param([string] $Port = '443')

    return [pscustomobject][ordered]@{
        schemaVersion = 1
        firewallProfiles = [pscustomobject][ordered]@{
            Domain = (New-NRFixtureFirewallProfile)
            Private = (New-NRFixtureFirewallProfile)
            Public = (New-NRFixtureFirewallProfile)
        }
        firewallDynamicKeywordAddresses = @()
        firewallRules = @((New-NRFixtureFirewallRuleRecord -LocalPort $Port))
        excludedFirewallRules = @()
        nrptRules = @((New-NRFixtureNrptRuleRecord))
    }
}

function New-NRFixtureCaptureSnapshot {
    [CmdletBinding()]
    param([object] $Configuration = (New-NRFixtureConfiguration))

    $persistentEntries = @(
        foreach ($record in @($Configuration.firewallRules)) {
            [pscustomobject]@{ Name = [string]$record.name; IsComplete = $true; MissingFilters = @(); FilterIssues = @(); Fields = @{} }
        }
    )
    return [pscustomobject][ordered]@{
        schemaVersion = 1
        capturedAt = (Get-Date).ToString('o')
        computerName = $env:COMPUTERNAME
        configuration = $Configuration
        comparison = [pscustomobject]@{
            persistentStore = [pscustomobject]@{ PolicyStore = 'PersistentStore'; RuleCount = $persistentEntries.Count; Entries = $persistentEntries; BulkFilterWarnings = @() }
            systemDefaults = [pscustomobject]@{ PolicyStore = 'SystemDefaults'; RuleCount = 0; Entries = @(); BulkFilterWarnings = @() }
            excludedProperties = @()
            arraySemantics = 'Array order is ignored; duplicate elements are retained.'
            stringSemantics = 'String values are compared case-sensitively.'
        }
    }
}
