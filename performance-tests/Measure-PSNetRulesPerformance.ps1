#requires -Version 5.1
[CmdletBinding()]
param(
    [string] $RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [ValidateSet('Measure', 'InitializeBaseline', 'Test')]
    [string] $Mode = 'Measure',
    [string] $BaselinePath,
    [string] $OutputPath,
    [ValidateRange(1, 10)] [int] $Iterations = 5,
    [ValidateRange(0, 3)] [int] $WarmupIterations = 1,
    [ValidateRange(0.1, 100.0)] [double] $RegressionLimitPercent = 5.0,
    [switch] $WorkloadCounters
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Keep the workload deterministic and independent of machine-specific
# configuration, Snapshot, State, or Firewall settings.
$script:NRPerformanceWorkload = [ordered]@{
    CurrentSnapshotRuleCount = 627
    PersistentRuleCount = 627
    SystemDefaultsRuleCount = 408
    DesiredRuleCount = 220
    ExcludedRuleCount = 5
    ManagedModifiedRuleCount = 22
    ManagedInSyncRuleCount = 198
    DefaultExcludedRuleCount = 188
    NewCandidateRuleCount = 214
    ExtraRuleProperties = 0
    ExtraFilterProperties = 0
    FilterTypesPerRule = 7
    ObjectShape = 'Native-shaped PSCustomObjects; Snapshot comparison fields are Value-only PSCustomObjects.'
}
$script:NRPerformanceRegressionLimitPercent = $RegressionLimitPercent

# Functions instrumented when -WorkloadCounters is supplied. The counters are
# a diagnosis tool: call counts are deterministic even when wall-clock timings
# are noisy, so they show where the per-item work concentrates and whether a
# change actually reduced it. Keep this list focused on the comparison and
# classification hot paths; the instrumentation function fails loudly if a
# listed function disappears from the module source.
$script:NRPerformanceCounterTargets = @(
    'ConvertTo-NRFirewallRuleComparisonEntry'
    'Get-NRFirewallFilterIndex'
    'Get-NRComparisonProperties'
    'ConvertTo-NRComparisonPlainValue'
    'ConvertTo-NRComparisonCanonicalPlainValue'
    'Test-NRComparisonPlainValuesEqual'
    'Test-NRComparisonFieldValuesEqual'
    'Test-NRCanonicalValuesEqual'
    'Get-NRMapByKey'
    'Get-NRProperty'
    'Get-NRPropertyNames'
    'Test-NRObjectLike'
    'Get-NRFirewallRuleClassification'
    'Format-NRFirewallRuleClassification'
    'Get-NRObjectChanges'
    'Get-NRPCustomObjectChanges'
    'Get-NRPCustomObjectPropertyChange'
    'Get-NRPCustomObjectPropertyNames'
    'Test-NRPropertyValueObjectLike'
    'Test-NRPropertyValuePairObjectLike'
    'Get-NRPairObjectChanges'
    'Test-NRCustomObjectPropertyValuesEqual'
    'Test-NRStringSequenceEqual'
    'Get-NRCompactValue'
    'Get-NRFirewallRuleDisplayInfo'
    'New-NRFirewallClassificationRecord'
    'Get-NRDefaultRuleStatus'
    'Assert-NRConfiguration'
    'Assert-NRFirewallRules'
    'Assert-NRFirewallRule'
    'Assert-NRFirewallRuleBody'
    'Assert-NRFirewallFilter'
    'Assert-NRObjectShape'
    'Assert-NRFieldType'
    'Get-NRFieldValueForValidation'
    'Test-NRFieldValue'
    'Test-NRNumberValue'
    'Test-NRScalarValue'
    'Test-NRStringArrayValue'
    'Test-NRStringOrArrayValue'
    'Assert-NRArrayField'
    'Test-NRProperty'
)

$RepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)
$modulePath = Join-Path $RepositoryRoot 'src\PSNetRules.psm1'
$fixturePath = Join-Path $RepositoryRoot 'tests\Fixtures\PSNetRules.TestFixtures.ps1'
foreach ($requiredPath in @($modulePath, $fixturePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required PSNetRules file not found: $requiredPath"
    }
}

if ($Mode -in @('InitializeBaseline', 'Test') -and [string]::IsNullOrWhiteSpace($BaselinePath)) {
    throw "-BaselinePath is required when Mode is '$Mode'."
}
if ($Mode -eq 'Measure' -and -not [string]::IsNullOrWhiteSpace($BaselinePath)) {
    throw '-BaselinePath is valid only with -Mode InitializeBaseline or -Mode Test.'
}

function Test-NRPerformanceFullyQualifiedPath {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $Path)

    if (-not [System.IO.Path]::IsPathRooted($Path)) { return $false }
    if ($Path -match '^[A-Za-z]:' -and ($Path.Length -lt 3 -or $Path[2] -notin @('\', '/'))) { return $false }
    if ($Path.StartsWith('\') -and -not $Path.StartsWith('\\')) { return $false }
    return $true
}

function Resolve-NRPerformancePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $BaseDirectory
    )

    if (Test-NRPerformanceFullyQualifiedPath -Path $Path) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    # Reject ambiguous drive-relative and root-relative paths. Resolve ordinary
    # relative paths from the repository root, not the caller's location or profile.
    if ([System.IO.Path]::IsPathRooted($Path)) {
        throw "Path must be fully qualified or relative to the repository root: $Path"
    }

    $basePath = [System.IO.Path]::GetFullPath($BaseDirectory)
    $fullPath = [System.IO.Path]::GetFullPath((Join-Path -Path $basePath -ChildPath $Path))
    $rootPrefix = $basePath
    if (-not $rootPrefix.EndsWith([string][System.IO.Path]::DirectorySeparatorChar)) {
        $rootPrefix += [System.IO.Path]::DirectorySeparatorChar
    }

    $isWithinRepository = [string]::Equals(
        $fullPath,
        $basePath,
        [System.StringComparison]::OrdinalIgnoreCase
    ) -or $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)

    if (-not $isWithinRepository) {
        throw "Relative paths must remain inside the repository root '$basePath': $Path"
    }

    return $fullPath
}

function Assert-NRPerformanceOutputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $BaseDirectory
    )

    $fullPath = Resolve-NRPerformancePath -Path $Path -BaseDirectory $BaseDirectory
    $directory = [System.IO.Path]::GetDirectoryName($fullPath)
    if (-not [System.IO.Directory]::Exists($directory)) {
        throw "Output directory does not exist. The benchmark will not create directories: $directory"
    }
    if ([System.IO.Directory]::Exists($fullPath)) {
        throw "Output path points to a directory: $fullPath"
    }
    if ([System.IO.File]::Exists($fullPath)) {
        throw "Refusing to overwrite an existing file: $fullPath"
    }
    return $fullPath
}

function Resolve-NRPerformanceInputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $BaseDirectory
    )

    $fullPath = Resolve-NRPerformancePath -Path $Path -BaseDirectory $BaseDirectory
    if (-not [System.IO.File]::Exists($fullPath)) {
        throw "Required performance baseline file not found: $fullPath"
    }
    return $fullPath
}

function Write-NRPerformanceJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [object] $InputObject,
        [Parameter(Mandatory = $true)] [string] $BaseDirectory
    )

    # Only explicitly requested outputs reach this writer. Parent directories
    # must exist, and CreateNew prevents overwriting an existing file.
    $fullPath = Assert-NRPerformanceOutputPath -Path $Path -BaseDirectory $BaseDirectory
    $json = ConvertTo-Json -InputObject $InputObject -Depth 20
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList $false
    $bytes = $encoding.GetBytes($json)
    $stream = [System.IO.File]::Open(
        $fullPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $stream.Dispose()
    }
    return $fullPath
}

function Add-NRPerformanceWorkloadCounterInstrumentation {
    param(
        [Parameter(Mandatory = $true)] [string] $Source,
        [Parameter(Mandatory = $true)] [string[]] $FunctionNames
    )

    # Insert a counter increment as the first statement of each target
    # function, located through the AST so the instrumentation follows the
    # code instead of depending on line numbers. The production source on
    # disk is never modified; only the in-memory copy is instrumented.
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Source, [ref]$tokens, [ref]$parseErrors)
    if ($null -ne $parseErrors -and $parseErrors.Count -gt 0) {
        throw ('Module source did not parse for workload-counter instrumentation: {0}' -f $parseErrors[0].Message)
    }

    $remaining = @{}
    foreach ($name in $FunctionNames) { $remaining[$name] = $true }
    $insertions = New-Object 'System.Collections.Generic.List[object]'
    $functionNodes = $ast.FindAll({
        param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)
    foreach ($node in $functionNodes) {
        if (-not $remaining.ContainsKey($node.Name)) { continue }
        $offset = if ($null -ne $node.Body.ParamBlock) {
            $node.Body.ParamBlock.Extent.EndOffset
        }
        else {
            $node.Body.Extent.StartOffset + 1
        }
        $insertions.Add([pscustomobject]@{ Name = $node.Name; Offset = $offset })
        $remaining.Remove($node.Name)
    }
    if ($remaining.Count -gt 0) {
        throw ('Workload-counter target function(s) not found in module source: {0}' -f `
            (@($remaining.Keys | Sort-Object) -join ', '))
    }

    # Drop a leading BOM so the prepended initialization stays the first
    # statement and no stray BOM lands mid-file.
    $builder = New-Object 'System.Text.StringBuilder' ($Source.TrimStart([char]0xFEFF))
    foreach ($insertion in @($insertions | Sort-Object Offset -Descending)) {
        $statement = "`n    `$script:NRWorkloadCounters['" + $insertion.Name + `
            "'] = 1 + [int]`$script:NRWorkloadCounters['" + $insertion.Name + "']"
        [void]$builder.Insert($insertion.Offset, $statement)
    }
    return "`$script:NRWorkloadCounters = @{}`n" + $builder.ToString()
}

function New-NRPerformanceCaptureSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PersistentStore', 'SystemDefaults')]
        [string] $PolicyStore,
        [Parameter(Mandatory = $true)] [int] $RuleCount
    )

    $rules = New-Object 'System.Collections.Generic.List[object]'
    $nativeIndexes = @{
        address = @{}
        application = @{}
        port = @{}
        service = @{}
        interface = @{}
        interfaceType = @{}
        security = @{}
    }
    $filterTypes = @(
        [pscustomobject]@{ JsonName = 'address'; Type = 'Address' },
        [pscustomobject]@{ JsonName = 'application'; Type = 'Application' },
        [pscustomobject]@{ JsonName = 'port'; Type = 'Port' },
        [pscustomobject]@{ JsonName = 'service'; Type = 'Service' },
        [pscustomobject]@{ JsonName = 'interface'; Type = 'Interface' },
        [pscustomobject]@{ JsonName = 'interfaceType'; Type = 'InterfaceType' },
        [pscustomobject]@{ JsonName = 'security'; Type = 'Security' }
    )

    for ($ruleIndex = 1; $ruleIndex -le $RuleCount; $ruleIndex++) {
        $name = 'PerfRule-{0:D4}' -f $ruleIndex
        $instanceId = 'PerfInstance-{0:D4}' -f $ruleIndex
        $ruleProperties = [ordered]@{
            Name = $name
            InstanceID = $instanceId
            DisplayName = $name
            Description = ('Synthetic firewall rule {0}' -f $ruleIndex)
            Group = 'PSNetRules Performance Fixture'
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
        $rules.Add((New-NRFixtureFirewallRuleObject -Properties $ruleProperties))

        foreach ($filterType in $filterTypes) {
            $filterProperties = @{}
            if ($filterType.Type -eq 'Port') {
                $filterProperties.LocalPort = @([string](40000 + ($ruleIndex % 20000)))
            }
            $filter = New-NRFixtureFirewallFilter -Type $filterType.Type `
                -InstanceId $instanceId -Properties $filterProperties
            $nativeIndexes[$filterType.JsonName][$instanceId] = $filter
        }
    }

    return [pscustomobject]@{
        PolicyStore = $PolicyStore
        Rules = $rules.ToArray()
        FilterIndexes = $nativeIndexes
    }
}

function ConvertTo-NRPerformanceSnapshotInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object] $Inventory)

    # Match the PSCustomObject shape produced by ConvertFrom-Json for Snapshot
    # comparison fields, without serializing and parsing the synthetic data.
    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($entry in $Inventory.Entries) {
        $fields = [ordered]@{}
        foreach ($fieldName in $entry.Fields.Keys) {
            $field = $entry.Fields[$fieldName]
            $valueProperty = $field.PSObject.Properties['Value']
            if ($null -ne $valueProperty) { $value = $valueProperty.Value }
            else { $value = $field }
            $fields[[string]$fieldName] = [pscustomobject]@{ Value = $value }
        }
        $entries.Add([pscustomobject]@{
            Name = [string]$entry.Name
            IsComplete = [bool]$entry.IsComplete
            MissingFilters = @($entry.MissingFilters)
            FilterIssues = @($entry.FilterIssues)
            Fields = [pscustomobject]$fields
        })
    }

    return [pscustomobject]@{
        PolicyStore = [string]$Inventory.PolicyStore
        RuleCount = [int]$Inventory.RuleCount
        Entries = $entries.ToArray()
        BulkFilterWarnings = @($Inventory.BulkFilterWarnings)
    }
}

function New-NRPerformanceConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [int] $CurrentRuleCount,
        [Parameter(Mandatory = $true)] [int] $DesiredRuleCount,
        [Parameter(Mandatory = $true)] [int] $ExcludedRuleCount
    )

    $profiles = [pscustomobject][ordered]@{
        Domain = New-NRFixtureFirewallProfile
        Private = New-NRFixtureFirewallProfile
        Public = New-NRFixtureFirewallProfile
    }
    $currentRecords = New-Object 'System.Collections.Generic.List[object]'
    $desiredRecords = New-Object 'System.Collections.Generic.List[object]'
    $managedNames = New-Object 'System.Collections.Generic.List[string]'
    $excludedNames = New-Object 'System.Collections.Generic.List[string]'

    for ($index = 1; $index -le $CurrentRuleCount; $index++) {
        $name = 'PerfRule-{0:D4}' -f $index
        $localPort = [string](40000 + ($index % 20000))
        $description = 'Synthetic firewall rule {0}' -f $index
        $group = 'PSNetRules Performance Fixture'
        $currentRecord = New-NRFixtureFirewallRuleRecord -Name $name -DisplayName $name `
            -Description $description -Group $group -Enabled 'True' -LocalPort $localPort
        $currentRecords.Add($currentRecord)

        if ($index -le $DesiredRuleCount) {
            # Keep the managed-rule status distribution constant across runs.
            $desiredPort = $localPort
            if (($index % 10) -eq 0) { $desiredPort = [string](40001 + ($index % 20000)) }
            $desiredRecords.Add((New-NRFixtureFirewallRuleRecord -Name $name `
                -DisplayName $name -Description $description -Group $group `
                -Enabled 'True' -LocalPort $desiredPort))
            $managedNames.Add($name)
        }
        elseif ($index -gt ($CurrentRuleCount - $ExcludedRuleCount)) {
            $excludedNames.Add($name)
        }
    }

    $currentConfiguration = [pscustomobject][ordered]@{
        schemaVersion = 1
        firewallProfiles = $profiles
        firewallDynamicKeywordAddresses = @()
        firewallRules = $currentRecords.ToArray()
        nrptRules = @()
    }
    $desiredConfiguration = [pscustomobject][ordered]@{
        schemaVersion = 1
        firewallProfiles = $profiles
        firewallDynamicKeywordAddresses = @()
        firewallRules = $desiredRecords.ToArray()
        nrptRules = @()
        excludedFirewallRules = $excludedNames.ToArray()
    }
    $state = [pscustomobject]@{
        schemaVersion = 1
        nrptRules = [pscustomobject]@{}
        managedFirewallRules = $managedNames.ToArray()
    }

    return [pscustomobject]@{
        Current = $currentConfiguration
        Desired = $desiredConfiguration
        State = $state
    }
}

function Measure-NRPerformanceAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Module,
        [Parameter(Mandatory = $true)] [string] $Name,
        [Parameter(Mandatory = $true)] [scriptblock] $Action,
        [hashtable] $Parameters = @{},
        [Parameter(Mandatory = $true)] [int] $Warmups,
        [Parameter(Mandatory = $true)] [int] $Count,
        [switch] $CaptureStageMetrics,
        [switch] $ResetWorkloadCounters
    )

    # Stage timings and the last scenario result are collected from the same
    # execution so individual metrics do not require repeated full pipelines.
    return (& $Module {
        param($MetricName, $MetricAction, $MetricParameters, $WarmupCount, $IterationCount, $CaptureStages, $ResetCounters)

        function script:Get-NRPerformanceHarnessStatistics {
            param([Parameter(Mandatory = $true)] [double[]] $Values)
            $orderedValues = @($Values | Sort-Object)
            $middle = [int][Math]::Floor($orderedValues.Count / 2)
            if (($orderedValues.Count % 2) -eq 1) { $median = $orderedValues[$middle] }
            else { $median = ($orderedValues[$middle - 1] + $orderedValues[$middle]) / 2.0 }
            return [pscustomobject]@{
                MedianMs = [Math]::Round($median, 3)
                MinMs = [Math]::Round($orderedValues[0], 3)
                MaxMs = [Math]::Round($orderedValues[$orderedValues.Count - 1], 3)
                SamplesMs = @($Values | ForEach-Object { [Math]::Round($_, 3) })
            }
        }

        # Reset by assigning a new hashtable: a snapshot taken by the caller
        # after a previous scenario keeps referring to the old one.
        if ($ResetCounters) { $script:NRWorkloadCounters = @{} }

        for ($warmup = 0; $warmup -lt $WarmupCount; $warmup++) {
            $null = & $MetricAction @MetricParameters
        }

        $totalSamples = New-Object 'System.Collections.Generic.List[double]'
        $stageSamples = @{}
        $lastData = $null
        for ($iteration = 0; $iteration -lt $IterationCount; $iteration++) {
            $timer = [System.Diagnostics.Stopwatch]::StartNew()
            $sampleResult = & $MetricAction @MetricParameters
            $timer.Stop()
            $totalSamples.Add([double]$timer.Elapsed.TotalMilliseconds)

            if ($CaptureStages) {
                if ($null -eq $sampleResult -or $null -eq $sampleResult.PSObject.Properties['Timings'] -or
                    $null -eq $sampleResult.PSObject.Properties['Data']) {
                    throw "Performance scenario '$MetricName' did not return Timings and Data."
                }
                foreach ($stage in $sampleResult.Timings.PSObject.Properties) {
                    if (-not $stageSamples.ContainsKey($stage.Name)) {
                        $stageSamples[$stage.Name] = New-Object 'System.Collections.Generic.List[double]'
                    }
                    $stageSamples[$stage.Name].Add([double]$stage.Value)
                }
                $lastData = $sampleResult.Data
            }
            else {
                $lastData = $sampleResult
            }
        }

        $totalMetric = Get-NRPerformanceHarnessStatistics -Values $totalSamples.ToArray()
        $stageMetrics = [ordered]@{}
        foreach ($stageName in @($stageSamples.Keys | Sort-Object)) {
            if ($stageSamples[$stageName].Count -ne $IterationCount) {
                throw "Performance scenario '$MetricName' did not report stage '$stageName' for every iteration."
            }
            $stageMetrics[$stageName] = Get-NRPerformanceHarnessStatistics -Values $stageSamples[$stageName].ToArray()
        }

        return [pscustomobject]@{
            Metric = $totalMetric
            StageMetrics = [pscustomobject]$stageMetrics
            Result = $lastData
        }
    } $Name $Action $Parameters $Warmups $Count ([bool]$CaptureStageMetrics) ([bool]$ResetWorkloadCounters))
}

function Get-NRPerformanceProperty {
    [CmdletBinding()]
    param([AllowNull()] [object] $InputObject, [Parameter(Mandatory = $true)] [string] $Name)

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Assert-NRPerformanceClassificationDistribution {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object[]] $Results)

    $counts = @{}
    foreach ($item in $Results) {
        $status = [string]$item.Status
        if (-not $counts.ContainsKey($status)) { $counts[$status] = 0 }
        $counts[$status]++
    }

    $expected = @{
        Modified = $script:NRPerformanceWorkload.ManagedModifiedRuleCount
        InSync = $script:NRPerformanceWorkload.ManagedInSyncRuleCount
        DefaultExcluded = $script:NRPerformanceWorkload.DefaultExcludedRuleCount
        NewCandidate = $script:NRPerformanceWorkload.NewCandidateRuleCount
        Excluded = $script:NRPerformanceWorkload.ExcludedRuleCount
    }
    foreach ($status in $expected.Keys) {
        $actualCount = if ($counts.ContainsKey($status)) { [int]$counts[$status] } else { 0 }
        if ($actualCount -ne [int]$expected[$status]) {
            throw ("Synthetic Diff workload mismatch for status '{0}': expected={1}; actual={2}." -f `
                $status, $expected[$status], $actualCount)
        }
    }
    if ($counts.Count -ne $expected.Count) {
        $unexpected = @($counts.Keys | Where-Object { -not $expected.ContainsKey($_) })
        if ($unexpected.Count -gt 0) {
            throw ('Synthetic Diff workload produced unexpected statuses: {0}.' -f ($unexpected -join ', '))
        }
    }
}

function Compare-NRPerformanceBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $CurrentReport,
        [Parameter(Mandatory = $true)] [object] $BaselineReport
    )

    if ([int]$BaselineReport.ReportVersion -ne [int]$CurrentReport.ReportVersion) {
        throw 'Performance baseline report version does not match.'
    }
    foreach ($field in @('PowerShellVersion', 'PSEdition', 'OperatingSystem', 'ProcessorCount', 'Is64BitProcess')) {
        $currentValue = [string](Get-NRPerformanceProperty -InputObject $CurrentReport.Environment -Name $field)
        $baselineValue = [string](Get-NRPerformanceProperty -InputObject $BaselineReport.Environment -Name $field)
        if ($currentValue -cne $baselineValue) {
            throw "Performance baseline environment mismatch for '$field': current='$currentValue'; baseline='$baselineValue'."
        }
    }
    foreach ($field in @(
        'CurrentSnapshotRuleCount', 'PersistentRuleCount', 'SystemDefaultsRuleCount', 'DesiredRuleCount',
        'ExcludedRuleCount', 'ManagedModifiedRuleCount', 'ManagedInSyncRuleCount',
        'DefaultExcludedRuleCount', 'NewCandidateRuleCount', 'ExtraRuleProperties',
        'ExtraFilterProperties', 'FilterTypesPerRule', 'ObjectShape'
    )) {
        $currentValue = [string](Get-NRPerformanceProperty -InputObject $CurrentReport.Workload -Name $field)
        $baselineValue = [string](Get-NRPerformanceProperty -InputObject $BaselineReport.Workload -Name $field)
        if ($currentValue -cne $baselineValue) {
            throw "Performance baseline workload mismatch for '$field': current='$currentValue'; baseline='$baselineValue'."
        }
    }

    foreach ($field in @('Iterations', 'WarmupIterations', 'RegressionLimitPercent')) {
        $currentValue = [string](Get-NRPerformanceProperty -InputObject $CurrentReport -Name $field)
        $baselineValue = [string](Get-NRPerformanceProperty -InputObject $BaselineReport -Name $field)
        if ($currentValue -cne $baselineValue) {
            throw "Performance baseline measurement setting mismatch for '$field': current='$currentValue'; baseline='$baselineValue'."
        }
    }

    $currentMetrics = $CurrentReport.Metrics
    $baselineMetrics = $BaselineReport.Metrics
    $currentNames = @($currentMetrics.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    $baselineNames = @($baselineMetrics.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
    if (($currentNames -join '|') -cne ($baselineNames -join '|')) {
        throw 'Performance baseline metric set does not match the current benchmark.'
    }

    $rows = New-Object 'System.Collections.Generic.List[object]'
    $regressionFound = $false
    foreach ($metricName in $currentNames) {
        $currentMetric = Get-NRPerformanceProperty -InputObject $currentMetrics -Name $metricName
        $baselineMetric = Get-NRPerformanceProperty -InputObject $baselineMetrics -Name $metricName
        $currentMedian = [double]$currentMetric.MedianMs
        $baselineMedian = [double]$baselineMetric.MedianMs
        if ($baselineMedian -le 0 -or $currentMedian -lt 0 -or
            [double]::IsNaN($baselineMedian) -or [double]::IsNaN($currentMedian) -or
            [double]::IsInfinity($baselineMedian) -or [double]::IsInfinity($currentMedian)) {
            throw "Invalid median value in performance metric '$metricName'."
        }

        $changePercent = (($currentMedian - $baselineMedian) / $baselineMedian) * 100.0
        $isRegression = ($changePercent -ge $script:NRPerformanceRegressionLimitPercent)
        if ($isRegression) { $regressionFound = $true }
        $rows.Add([pscustomobject]@{
            Metric = $metricName
            BaselineMedianMs = [Math]::Round($baselineMedian, 3)
            CurrentMedianMs = [Math]::Round($currentMedian, 3)
            ChangePercent = [Math]::Round($changePercent, 3)
            Result = if ($isRegression) { 'FAIL' } else { 'PASS' }
        })
    }

    return [pscustomobject]@{
        Rows = $rows.ToArray()
        RegressionFound = $regressionFound
    }
}

$resolvedBaselinePath = $null
if (-not [string]::IsNullOrWhiteSpace($BaselinePath)) {
    if ($Mode -eq 'Test') {
        $resolvedBaselinePath = Resolve-NRPerformanceInputPath -Path $BaselinePath -BaseDirectory $RepositoryRoot
    }
    else {
        $resolvedBaselinePath = Assert-NRPerformanceOutputPath -Path $BaselinePath -BaseDirectory $RepositoryRoot
    }
}
$resolvedOutputPath = $null
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $resolvedOutputPath = Assert-NRPerformanceOutputPath -Path $OutputPath -BaseDirectory $RepositoryRoot
}
if ($null -ne $resolvedBaselinePath -and $null -ne $resolvedOutputPath -and
    [string]::Equals($resolvedBaselinePath, $resolvedOutputPath, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BaselinePath and OutputPath must refer to different files.'
}

$baselineReport = $null
if ($Mode -eq 'Test') {
    $baselineJson = [System.IO.File]::ReadAllText($resolvedBaselinePath, [System.Text.Encoding]::UTF8)
    $baselineReport = ConvertFrom-Json -InputObject $baselineJson -ErrorAction Stop
    if ($null -eq $baselineReport -or $null -eq $baselineReport.PSObject.Properties['Metrics']) {
        throw 'Performance baseline file does not contain a valid benchmark report.'
    }
}

$module = $null
$benchmarkTimer = [System.Diagnostics.Stopwatch]::StartNew()
try {
    # Load the module source into an in-memory module. This avoids Import-Module
    # and its Windows PowerShell 5.1 analysis cache under the user profile; no
    # module files are copied to or written under the user profile.
    $moduleSource = [System.IO.File]::ReadAllText($modulePath)
    if ($WorkloadCounters) {
        $moduleSource = Add-NRPerformanceWorkloadCounterInstrumentation `
            -Source $moduleSource -FunctionNames $script:NRPerformanceCounterTargets
    }
    $moduleScriptBlock = [scriptblock]::Create($moduleSource)
    $module = New-Module -Name 'PSNetRulesPerformanceHarness' -ScriptBlock $moduleScriptBlock

    # A ScriptBlock-backed module has no PSCommandPath. Restore the source path
    # used by generated-script preflight checks in the module's own scope.
    & $module {
        param([string] $ModulePath)
        $script:NRModulePath = $ModulePath
    } $modulePath

    # Confirm that the in-memory module exposes the private functions required
    # by the benchmark before entering any measured scenario.
    $moduleLoadCheck = & $module {
        [pscustomobject]@{
            HasComparisonInventory = ($null -ne (Get-Command -Name Get-NRFirewallRuleComparisonInventory -CommandType Function -ErrorAction SilentlyContinue))
            HasClassifier = ($null -ne (Get-Command -Name Get-NRFirewallRuleClassification -CommandType Function -ErrorAction SilentlyContinue))
            HasFormatter = ($null -ne (Get-Command -Name Format-NRFirewallRuleClassification -CommandType Function -ErrorAction SilentlyContinue))
            ModulePath = [string]$script:NRModulePath
        }
    }
    if (-not $moduleLoadCheck.HasComparisonInventory -or -not $moduleLoadCheck.HasClassifier -or
        -not $moduleLoadCheck.HasFormatter -or $moduleLoadCheck.ModulePath -cne $modulePath) {
        throw 'PSNetRules source did not initialize correctly in the in-memory benchmark module.'
    }

    # Reuse the correctness-test builders. Dot-sourcing the fixture file only
    # defines functions; it does not access user settings or write files.
    . $fixturePath

    $setupTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $persistentSource = New-NRPerformanceCaptureSource -PolicyStore PersistentStore `
        -RuleCount $script:NRPerformanceWorkload.PersistentRuleCount
    $defaultsSource = New-NRPerformanceCaptureSource -PolicyStore SystemDefaults `
        -RuleCount $script:NRPerformanceWorkload.SystemDefaultsRuleCount
    $configurationSet = New-NRPerformanceConfiguration `
        -CurrentRuleCount $script:NRPerformanceWorkload.PersistentRuleCount `
        -DesiredRuleCount $script:NRPerformanceWorkload.DesiredRuleCount `
        -ExcludedRuleCount $script:NRPerformanceWorkload.ExcludedRuleCount

    # Supply fixed SystemDefaults Rule and Filter results through module-local
    # cmdlet substitutes. The production inventory path runs without loading
    # NetSecurity or invoking Windows Firewall cmdlets.
    & $module {
        param($SyntheticSource)
        $script:NRPerformanceSystemDefaultsSource = $SyntheticSource

        function script:Get-NRPerformanceSyntheticFilters {
            param([string] $JsonName, [AllowNull()] [object] $AssociatedNetFirewallRule)
            $index = $script:NRPerformanceSystemDefaultsSource.FilterIndexes[$JsonName]
            if ($null -ne $AssociatedNetFirewallRule) {
                $instanceId = [string]$AssociatedNetFirewallRule.InstanceID
                if ($index.ContainsKey($instanceId)) { return @($index[$instanceId]) }
                return @()
            }
            return @($index.Values)
        }

        function script:Get-NetFirewallRule {
            [CmdletBinding()]
            param([string] $PolicyStore, [switch] $All)
            if ($PolicyStore -cne 'SystemDefaults') { throw "Unexpected synthetic PolicyStore: $PolicyStore" }
            return @($script:NRPerformanceSystemDefaultsSource.Rules)
        }
        function script:Get-NetFirewallAddressFilter {
            [CmdletBinding()]
            param([string] $PolicyStore, [switch] $All, [object] $AssociatedNetFirewallRule)
            Get-NRPerformanceSyntheticFilters -JsonName 'address' -AssociatedNetFirewallRule $AssociatedNetFirewallRule
        }
        function script:Get-NetFirewallApplicationFilter {
            [CmdletBinding()]
            param([string] $PolicyStore, [switch] $All, [object] $AssociatedNetFirewallRule)
            Get-NRPerformanceSyntheticFilters -JsonName 'application' -AssociatedNetFirewallRule $AssociatedNetFirewallRule
        }
        function script:Get-NetFirewallPortFilter {
            [CmdletBinding()]
            param([string] $PolicyStore, [switch] $All, [object] $AssociatedNetFirewallRule)
            Get-NRPerformanceSyntheticFilters -JsonName 'port' -AssociatedNetFirewallRule $AssociatedNetFirewallRule
        }
        function script:Get-NetFirewallServiceFilter {
            [CmdletBinding()]
            param([string] $PolicyStore, [switch] $All, [object] $AssociatedNetFirewallRule)
            Get-NRPerformanceSyntheticFilters -JsonName 'service' -AssociatedNetFirewallRule $AssociatedNetFirewallRule
        }
        function script:Get-NetFirewallInterfaceFilter {
            [CmdletBinding()]
            param([string] $PolicyStore, [switch] $All, [object] $AssociatedNetFirewallRule)
            Get-NRPerformanceSyntheticFilters -JsonName 'interface' -AssociatedNetFirewallRule $AssociatedNetFirewallRule
        }
        function script:Get-NetFirewallInterfaceTypeFilter {
            [CmdletBinding()]
            param([string] $PolicyStore, [switch] $All, [object] $AssociatedNetFirewallRule)
            Get-NRPerformanceSyntheticFilters -JsonName 'interfaceType' -AssociatedNetFirewallRule $AssociatedNetFirewallRule
        }
        function script:Get-NetFirewallSecurityFilter {
            [CmdletBinding()]
            param([string] $PolicyStore, [switch] $All, [object] $AssociatedNetFirewallRule)
            Get-NRPerformanceSyntheticFilters -JsonName 'security' -AssociatedNetFirewallRule $AssociatedNetFirewallRule
        }

        foreach ($commandName in @(
            'Get-NetFirewallRule', 'Get-NetFirewallAddressFilter', 'Get-NetFirewallApplicationFilter',
            'Get-NetFirewallPortFilter', 'Get-NetFirewallServiceFilter', 'Get-NetFirewallInterfaceFilter',
            'Get-NetFirewallInterfaceTypeFilter', 'Get-NetFirewallSecurityFilter'
        )) {
            $command = Get-Command -Name $commandName -CommandType Function -ErrorAction Stop
            if ($command.ModuleName -cne 'PSNetRulesPerformanceHarness') {
                throw "The synthetic $commandName function did not resolve inside the in-memory benchmark module. Refusing to run any Firewall query."
            }
        }
    } $defaultsSource
    $setupTimer.Stop()
    $setupMilliseconds = [Math]::Round($setupTimer.Elapsed.TotalMilliseconds, 1)

    # Define measured actions in the module session state so they can call
    # private PSNetRules functions without exporting those functions.
    $moduleActions = & $module {
        [pscustomobject]@{
            CapturePostEnumeration = {
                param($PersistentSource, $Configuration, $Desired, $State, $ExcludedProperties)
                $persistentTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $persistent = Get-NRFirewallRuleComparisonInventory -PolicyStore PersistentStore -CaptureSource $PersistentSource
                $persistentTimer.Stop()

                $defaultsTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $defaults = Get-NRFirewallRuleComparisonInventory -PolicyStore SystemDefaults
                $defaultsTimer.Stop()

                $validationTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $persistentIncomplete = @($persistent.Entries | Where-Object { -not $_.IsComplete })
                $defaultsIncomplete = @($defaults.Entries | Where-Object { -not $_.IsComplete })
                if ($persistentIncomplete.Count -gt 0 -or $defaultsIncomplete.Count -gt 0) {
                    throw 'Synthetic Capture inventory contains incomplete rules.'
                }
                $configurationNames = Get-NRMapByKey -Items @($Configuration.firewallRules) -KeyProperty 'name'
                $comparisonNames = Get-NRMapByKey -Items @($persistent.Entries) -KeyProperty 'Name'
                if ($configurationNames.Count -ne $comparisonNames.Count -or
                    @($configurationNames.Keys | Where-Object { -not $comparisonNames.ContainsKey($_) }).Count -gt 0) {
                    throw 'Synthetic Capture configuration and PersistentStore inventory names do not match.'
                }
                $null = Get-NRMapByKey -Items @($defaults.Entries) -KeyProperty 'Name'
                $validationTimer.Stop()

                $assemblyTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $comparison = [pscustomobject]@{
                    persistentStore = $persistent
                    systemDefaults = $defaults
                    excludedProperties = @($ExcludedProperties)
                    arraySemantics = 'Array order is ignored; duplicate elements are retained.'
                    stringSemantics = 'String values are compared case-sensitively.'
                }
                $snapshot = [pscustomobject][ordered]@{
                    schemaVersion = 1
                    capturedAt = '2000-01-01T00:00:00.0000000Z'
                    computerName = 'PSNETRULES-PERFORMANCE-FIXTURE'
                    configuration = $Configuration
                    comparison = $comparison
                }
                $assemblyTimer.Stop()

                # Measure the production managed-name calculation in memory;
                # the benchmark does not read or write the State sidecar.
                $stateUpdateTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $updatedManagedNames = @(Get-NRCaptureManagedFirewallRuleNames `
                    -CurrentFirewallRules @($Configuration.firewallRules) `
                    -DesiredFirewallRules @($Desired.firewallRules) `
                    -PreviouslyManagedNames @($State.managedFirewallRules) `
                    -ExcludedNames @(Get-NRExcludedFirewallRuleNames -Configuration $Desired))
                $stateUpdateTimer.Stop()
                if ($updatedManagedNames.Count -ne $Desired.firewallRules.Count) {
                    throw ('Synthetic Capture managed-state update mismatch: expected={0}; actual={1}.' -f `
                        $Desired.firewallRules.Count, $updatedManagedNames.Count)
                }

                # Use the production compression settings but retain the JSON
                # string in memory; this stage performs no file I/O or parse.
                $serializationTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $snapshotJson = ConvertTo-Json -InputObject $snapshot -Depth 100 -Compress
                $serializationTimer.Stop()
                $snapshotJsonCharacterCount = $snapshotJson.Length
                $snapshotJson = $null

                return [pscustomobject]@{
                    Timings = [pscustomobject][ordered]@{
                        Capture_InventoryProjection_PersistentStore = [Math]::Round($persistentTimer.Elapsed.TotalMilliseconds, 3)
                        Capture_InventoryProjection_SystemDefaults = [Math]::Round($defaultsTimer.Elapsed.TotalMilliseconds, 3)
                        Capture_InventoryValidation = [Math]::Round($validationTimer.Elapsed.TotalMilliseconds, 3)
                        Capture_SnapshotObjectAssembly = [Math]::Round($assemblyTimer.Elapsed.TotalMilliseconds, 3)
                        Capture_ManagedStateUpdate = [Math]::Round($stateUpdateTimer.Elapsed.TotalMilliseconds, 3)
                        Capture_SnapshotJsonSerialization = [Math]::Round($serializationTimer.Elapsed.TotalMilliseconds, 3)
                    }
                    Data = [pscustomobject]@{
                        PersistentInventory = $persistent
                        DefaultsInventory = $defaults
                        Snapshot = $snapshot
                        UpdatedManagedNames = $updatedManagedNames
                        SnapshotJsonCharacterCount = $snapshotJsonCharacterCount
                    }
                }
            }
            DiffPipeline = {
                param($Snapshot, $Desired, $State, $PersistentByName, $DefaultsByName, $CurrentByName, $DesiredByName)
                $pipelineTimer = [System.Diagnostics.Stopwatch]::StartNew()

                $validationTimer = [System.Diagnostics.Stopwatch]::StartNew()
                Assert-NRConfiguration -Configuration $Desired | Out-Null
                $validationTimer.Stop()

                $classificationTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $ruleResults = @(Get-NRFirewallRuleClassification -Snapshot $Snapshot -Desired $Desired -State $State)
                $classificationTimer.Stop()

                $formattingTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $firewallLines = @(Format-NRFirewallRuleClassification -Results $ruleResults)
                $formattingTimer.Stop()

                $otherDiffTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $otherCurrent = [pscustomobject][ordered]@{
                    schemaVersion = $Snapshot.configuration.schemaVersion
                    firewallProfiles = $Snapshot.configuration.firewallProfiles
                    firewallDynamicKeywordAddresses = $Snapshot.configuration.firewallDynamicKeywordAddresses
                    nrptRules = $Snapshot.configuration.nrptRules
                }
                $otherChanges = @(Get-NRDiff -Desired $Desired -Current $otherCurrent -SkipFirewallRules)
                $otherLines = @(Format-NRDiff -Changes $otherChanges)
                $null = $firewallLines.Count + $otherLines.Count
                $otherDiffTimer.Stop()

                $pipelineTimer.Stop()

                # Run the two isolated comparison diagnostics once after the
                # full pipeline. They are excluded from pipeline timing.
                $defaultStatusTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $statusCount = 0
                foreach ($name in @($PersistentByName.Keys | Sort-Object)) {
                    $null = Get-NRDefaultRuleStatus -Name $name `
                        -PersistentComparisonByName $PersistentByName -SystemDefaultsByName $DefaultsByName
                    $statusCount++
                }
                $defaultStatusTimer.Stop()

                $managedChangesTimer = [System.Diagnostics.Stopwatch]::StartNew()
                $changeCount = 0
                foreach ($name in @($DesiredByName.Keys | Sort-Object)) {
                    $changes = @(Get-NRObjectChanges -Before $CurrentByName[$name] -After $DesiredByName[$name])
                    $changeCount += $changes.Count
                }
                $managedChangesTimer.Stop()

                return [pscustomobject]@{
                    Timings = [pscustomobject][ordered]@{
                        Diff_DesiredConfigurationValidation = [Math]::Round($validationTimer.Elapsed.TotalMilliseconds, 3)
                        Diff_FirewallClassification = [Math]::Round($classificationTimer.Elapsed.TotalMilliseconds, 3)
                        Diff_FirewallFormatting = [Math]::Round($formattingTimer.Elapsed.TotalMilliseconds, 3)
                        Diff_NonFirewallDiffAndFormatting = [Math]::Round($otherDiffTimer.Elapsed.TotalMilliseconds, 3)
                        Diff_InMemoryPipelineTotal = [Math]::Round($pipelineTimer.Elapsed.TotalMilliseconds, 3)
                        Diff_DefaultStatus = [Math]::Round($defaultStatusTimer.Elapsed.TotalMilliseconds, 3)
                        Diff_ManagedRuleObjectChanges = [Math]::Round($managedChangesTimer.Elapsed.TotalMilliseconds, 3)
                    }
                    Data = [pscustomobject]@{
                        ClassificationResults = $ruleResults
                        DiagnosticStatusCount = $statusCount
                        DiagnosticChangeCount = $changeCount
                    }
                }
            }
        }
    }

    Write-Host ('Synthetic workload (fixed): Snapshot={0}, PersistentStore={1}, SystemDefaults={2}, Desired={3}, Managed={3}, Excluded={4}' -f `
        $script:NRPerformanceWorkload.CurrentSnapshotRuleCount, `
        $script:NRPerformanceWorkload.PersistentRuleCount, `
        $script:NRPerformanceWorkload.SystemDefaultsRuleCount, `
        $script:NRPerformanceWorkload.DesiredRuleCount, `
        $script:NRPerformanceWorkload.ExcludedRuleCount)
    Write-Host ('Synthetic data setup: {0:N1} ms (one-time; excluded from measurements)' -f $setupMilliseconds)
    Write-Host ('Iterations: {0}; warmups: {1}; regression limit: {2:N0}%' -f `
        $Iterations, $WarmupIterations, $script:NRPerformanceRegressionLimitPercent)
    Write-Host ''

    $metrics = [ordered]@{}
    Write-Host 'Measuring Capture post-enumeration work...'
    $captureMeasurement = Measure-NRPerformanceAction `
        -Module $module -Name 'Capture_PostEnumerationTotal' -Action $moduleActions.CapturePostEnumeration `
        -Parameters @{ PersistentSource = $persistentSource; Configuration = $configurationSet.Current; `
            Desired = $configurationSet.Desired; State = $configurationSet.State; `
            ExcludedProperties = @(& $module { return ,@($script:NRComparisonExcludedProperties) }) } `
        -Warmups $WarmupIterations -Count $Iterations -CaptureStageMetrics `
        -ResetWorkloadCounters:$WorkloadCounters
    $captureWorkloadCounters = $null
    if ($WorkloadCounters) {
        $captureWorkloadCounters = & $module { return $script:NRWorkloadCounters }
    }
    foreach ($stageMetric in $captureMeasurement.StageMetrics.PSObject.Properties) {
        $metrics[$stageMetric.Name] = $stageMetric.Value
    }
    $metrics['Capture_PostEnumerationTotal'] = $captureMeasurement.Metric

    # Reuse inventories from the measured Capture scenario so Diff input
    # preparation does not add another full comparison-inventory pass.
    $rawInventories = $captureMeasurement.Result
    Write-Host ('Synthetic compressed Snapshot JSON: {0:N0} characters (in-memory only)' -f `
        $rawInventories.SnapshotJsonCharacterCount)

    $diffPreparationTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $persistentForDiff = ConvertTo-NRPerformanceSnapshotInventory -Inventory $rawInventories.PersistentInventory
    $defaultsForDiff = ConvertTo-NRPerformanceSnapshotInventory -Inventory $rawInventories.DefaultsInventory
    $snapshotForDiff = & $module {
        param($CapturedSnapshot, $PersistentInventory, $DefaultsInventory)
        $CapturedSnapshot.comparison.persistentStore = $PersistentInventory
        $CapturedSnapshot.comparison.systemDefaults = $DefaultsInventory
        return $CapturedSnapshot
    } $rawInventories.Snapshot $persistentForDiff $defaultsForDiff

    $diffIndexes = & $module {
        param($Snapshot, $Desired)
        return [pscustomobject]@{
            PersistentByName = Get-NRMapByKey -Items @($Snapshot.comparison.persistentStore.Entries) -KeyProperty 'Name'
            DefaultsByName = Get-NRMapByKey -Items @($Snapshot.comparison.systemDefaults.Entries) -KeyProperty 'Name'
            CurrentByName = Get-NRMapByKey -Items @($Snapshot.configuration.firewallRules) -KeyProperty 'name'
            DesiredByName = Get-NRMapByKey -Items @($Desired.firewallRules) -KeyProperty 'name'
        }
    } $snapshotForDiff $configurationSet.Desired
    $diffPreparationTimer.Stop()
    $diffPreparationMilliseconds = [Math]::Round($diffPreparationTimer.Elapsed.TotalMilliseconds, 1)

    Write-Host ('Diff input preparation: {0:N1} ms (one-time; excluded from measurements)' -f $diffPreparationMilliseconds)
    Write-Host 'Measuring Diff in-memory work...'
    $diffMeasurement = Measure-NRPerformanceAction `
        -Module $module -Name 'Diff_InMemoryScenario' -Action $moduleActions.DiffPipeline `
        -Parameters @{
            Snapshot = $snapshotForDiff
            Desired = $configurationSet.Desired
            State = $configurationSet.State
            PersistentByName = $diffIndexes.PersistentByName
            DefaultsByName = $diffIndexes.DefaultsByName
            CurrentByName = $diffIndexes.CurrentByName
            DesiredByName = $diffIndexes.DesiredByName
        } -Warmups $WarmupIterations -Count $Iterations -CaptureStageMetrics `
        -ResetWorkloadCounters:$WorkloadCounters
    $diffWorkloadCounters = $null
    if ($WorkloadCounters) {
        $diffWorkloadCounters = & $module { return $script:NRWorkloadCounters }
    }
    foreach ($stageMetric in $diffMeasurement.StageMetrics.PSObject.Properties) {
        $metrics[$stageMetric.Name] = $stageMetric.Value
    }
    Assert-NRPerformanceClassificationDistribution -Results @($diffMeasurement.Result.ClassificationResults)
    $benchmarkTimer.Stop()
    $benchmarkElapsedMilliseconds = [Math]::Round($benchmarkTimer.Elapsed.TotalMilliseconds, 1)
    Write-Host ('Benchmark setup + measurement elapsed: {0:N1} seconds' -f ($benchmarkElapsedMilliseconds / 1000.0))

    $report = [pscustomobject][ordered]@{
        ReportVersion = 2
        GeneratedAt = (Get-Date).ToString('o')
        Environment = [pscustomobject][ordered]@{
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            PSEdition = if ($PSVersionTable.ContainsKey('PSEdition')) { $PSVersionTable.PSEdition } else { 'Desktop' }
            OperatingSystem = [Environment]::OSVersion.VersionString
            ProcessorCount = [Environment]::ProcessorCount
            Is64BitProcess = [Environment]::Is64BitProcess
        }
        Workload = [pscustomobject]$script:NRPerformanceWorkload
        SetupMilliseconds = $setupMilliseconds
        DiffInputPreparationMilliseconds = $diffPreparationMilliseconds
        BenchmarkElapsedMilliseconds = $benchmarkElapsedMilliseconds
        Iterations = $Iterations
        WarmupIterations = $WarmupIterations
        RegressionLimitPercent = $script:NRPerformanceRegressionLimitPercent
        Metrics = [pscustomobject]$metrics
        Scope = 'CPU-only post-enumeration Capture and in-memory Diff. Metric timers exclude OS Firewall acquisition and data-file I/O; optional baseline/report file I/O occurs outside timed sections.'
    }
    if ($WorkloadCounters) {
        # Counts accumulate over every execution of the scenario in this run
        # (warmups + measured iterations). Run with -WarmupIterations 0 and
        # -Iterations 1 for exact per-pass counts.
        $report | Add-Member -NotePropertyName WorkloadCounters -NotePropertyValue ([pscustomobject][ordered]@{
            ExecutionsPerScenario = $WarmupIterations + $Iterations
            Capture = [pscustomobject]$captureWorkloadCounters
            Diff = [pscustomobject]$diffWorkloadCounters
        })
    }

    Write-Host ''
    Write-Host 'PSNetRules performance results (milliseconds; median):'
    $metricRows = foreach ($metricProperty in $report.Metrics.PSObject.Properties) {
        [pscustomobject]@{
            Metric = $metricProperty.Name
            MedianMs = $metricProperty.Value.MedianMs
            MinMs = $metricProperty.Value.MinMs
            MaxMs = $metricProperty.Value.MaxMs
        }
    }
    $metricRows | Format-Table -AutoSize

    if ($WorkloadCounters) {
        foreach ($scenarioName in @('Capture', 'Diff')) {
            Write-Host ''
            Write-Host ('Workload counters ({0}; totals over {1} execution(s) of the scenario):' -f `
                $scenarioName, ($WarmupIterations + $Iterations))
            $counterRows = foreach ($counterProperty in $report.WorkloadCounters.$scenarioName.PSObject.Properties) {
                [pscustomobject]@{ Function = $counterProperty.Name; Calls = [int]$counterProperty.Value }
            }
            $counterRows | Sort-Object Calls -Descending | Format-Table -AutoSize
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
        $writtenReport = Write-NRPerformanceJsonFile -Path $resolvedOutputPath -InputObject $report -BaseDirectory $RepositoryRoot
        Write-Host ('Report written to explicitly supplied path: {0}' -f $writtenReport)
    }

    if ($Mode -eq 'InitializeBaseline') {
        $writtenPath = Write-NRPerformanceJsonFile -Path $resolvedBaselinePath -InputObject $report -BaseDirectory $RepositoryRoot
        Write-Host ('Baseline created at explicitly supplied path: {0}' -f $writtenPath)
    }
    elseif ($Mode -eq 'Test') {
        $comparison = Compare-NRPerformanceBaseline -CurrentReport $report -BaselineReport $baselineReport
        Write-Host ''
        Write-Host ('Performance regression gate (failure at {0:N0}% or more):' -f $script:NRPerformanceRegressionLimitPercent)
        $comparison.Rows | Format-Table -AutoSize
        if ($comparison.RegressionFound) {
            throw ('Performance regression gate failed: at least one metric is {0:N0}% or more slower than its fixed baseline.' -f $script:NRPerformanceRegressionLimitPercent)
        }
        Write-Host 'Performance regression gate passed.'
    }

}
finally {
    if ($null -ne $module) {
        Remove-Module -ModuleInfo $module -Force -ErrorAction SilentlyContinue
    }
}
