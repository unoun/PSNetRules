<#
.SYNOPSIS
Capture, review, validate, adopt, unmanage, and generate changes for local Windows Firewall and DNS NRPT configuration.

.DESCRIPTION
PSNetRules uses a desired-state workflow. Capture records the current local configuration and a Firewall Rule comparison Snapshot. Review differences, explicitly select the Firewall Rules to manage, and generate a PowerShell script for applying reviewed changes.
Run without a command to display this help.

.PARAMETER Command
Operation to perform: capture, diff, validate, adopt, unmanage, generate, or search.

.PARAMETER Path
Desired-state JSON file. Defaults to .\network-rules.json. The Snapshot and State sidecars are stored beside this file.

.PARAMETER Force
Allow generate to overwrite an existing generated script. Valid only with generate.

.PARAMETER New
Adopt all current NewCandidate Firewall Rules. Valid only with adopt and cannot be combined with -Update, -Rename, or -Name.

.PARAMETER Update
Replace the desired representation of the named adopted Firewall Rule with its latest captured representation. Valid only with adopt and -Name.

.PARAMETER Rename
Accept uniquely matched name-only replacements reported by diff. Without -Name, accept all detected replacements; with -Name, specify the old Name.

.PARAMETER Nrpt
Adopt NRPT Rules instead of Firewall Rules. Valid only with adopt and -Name, where each -Name value is an NRPT Rule id from the latest capture (typically the Windows-assigned GUID name). Cannot be combined with -New or -Rename. Adopted NRPT Rules keep their captured id; no logical name is assigned.

.PARAMETER Name
For adopt, select Firewall Rule Names to adopt, or to update when used with -Update. With -Rename, specify old Names. With -Nrpt, specify NRPT Rule ids instead. For unmanage, exclude the named Rules from management without changing Windows Firewall.

.PARAMETER OutputPath
Output file for the generated PowerShell script. Valid only with generate. Defaults to a .generate.ps1 file beside the desired-state file.

.PARAMETER Status
Filter diff output to one Firewall Rule classification status, such as NewCandidate, Modified, Rename, or Excluded. Valid only with diff.

.PARAMETER Source
Where search looks: Snapshot (the latest capture) or Desired (the desired-state file). Defaults to Snapshot. Valid only with search.

.PARAMETER Text
Case-insensitive substring matched against the string representation of every Firewall Rule field. Valid only with search.

.PARAMETER Direction
Filter search results to Inbound or Outbound Rules. Valid only with search.

.PARAMETER Action
Filter search results to Allow or Block Rules. Valid only with search.

.PARAMETER Enabled
Filter search results to enabled Rules. Cannot be combined with -Disabled. Valid only with search.

.PARAMETER Disabled
Filter search results to disabled Rules. Cannot be combined with -Enabled. Valid only with search.

.PARAMETER Profile
Case-insensitive substring matched against the Profile field. Valid only with search.

.PARAMETER NamePattern
Case-insensitive substring matched against the Rule Name and DisplayName. Valid only with search.

.PARAMETER Program
Case-insensitive substring matched against the Program field. Valid only with search.

.PARAMETER Service
Case-insensitive substring matched against the Service field. Valid only with search.

.PARAMETER Protocol
Case-insensitive substring matched against the Protocol field. Valid only with search.

.PARAMETER LocalPort
Exact match against an entry of the LocalPort list. Valid only with search.

.PARAMETER RemotePort
Exact match against an entry of the RemotePort list. Valid only with search.

.PARAMETER LocalAddress
Case-insensitive substring matched against entries of the LocalAddress list. Valid only with search.

.PARAMETER RemoteAddress
Case-insensitive substring matched against entries of the RemoteAddress list. Valid only with search.

.PARAMETER Sid
Case-insensitive substring matched against the LocalUser, RemoteUser, and RemoteMachine SDDL strings. Valid only with search.

.PARAMETER MissingProgram
Restrict search results to Rules whose Program file does not exist on this computer. Paths that cannot be verified (relative paths, paths containing %, or access errors) are reported as Unverifiable instead of Missing. Valid only with search.

.EXAMPLE
.\PSNetRules.ps1
Display this help.

.EXAMPLE
.\PSNetRules.ps1 capture
Capture the current local configuration. Requires elevation.

.EXAMPLE
.\PSNetRules.ps1 diff -Status NewCandidate
Show current Firewall Rules available for adoption.

.EXAMPLE
.\PSNetRules.ps1 validate -Path .\network-rules.json
Validate the desired-state configuration.

.EXAMPLE
.\PSNetRules.ps1 adopt -New -WhatIf
Preview adoption of all NewCandidate Firewall Rules.

.EXAMPLE
.\PSNetRules.ps1 adopt -Update -Name 'Rule-Name'
Update one adopted Rule from the latest capture.

.EXAMPLE
.\PSNetRules.ps1 adopt -Rename -Name 'Old-Rule-Name' -WhatIf
Preview acceptance of one detected name-only replacement.

.EXAMPLE
.\PSNetRules.ps1 adopt -Nrpt -Name '{F8B4324F-A698-4BBB-A153-12F651B64F2F}'
Adopt one captured NRPT Rule into the desired state under its captured id.

.EXAMPLE
.\PSNetRules.ps1 unmanage -Name 'Rule-Name' -WhatIf
Preview excluding a Rule from management without deleting it from Windows.

.EXAMPLE
.\PSNetRules.ps1 generate -OutputPath .\network-rules.generate.ps1
Generate a reviewable PowerShell change script.

.EXAMPLE
.\PSNetRules.ps1 search -Direction Inbound -Action Allow
Search the latest capture snapshot for inbound Allow Rules.

.EXAMPLE
.\PSNetRules.ps1 search -MissingProgram
List captured Rules whose Program file no longer exists.

.NOTES
The generated script requires an elevated Windows PowerShell 5.1 session. Review it before execution. Run Unit tests before Contract tests, and Contract tests before Integration tests.
#>
#requires -Version 5.1
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', 'Profile', Justification = 'The search -Profile parameter filters Firewall Rule profiles; as a declared parameter it shadows the automatic $PROFILE variable only inside this script, by design.')]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet('capture', 'diff', 'validate', 'adopt', 'unmanage', 'generate', 'search')]
    [string] $Command,

    [Parameter(Position = 1)]
    [string] $Path = '.\network-rules.json',

    [switch] $Force,

    [switch] $New,

    [switch] $Update,

    [switch] $Rename,

    [switch] $Nrpt,

    [string[]] $Name,

    [string] $OutputPath,

    [ValidateSet('NewCandidate', 'Excluded', 'ExcludedMissing', 'DefaultExcluded', 'ComparisonInconclusive', 'InSync', 'Modified', 'Rename', 'Missing', 'DeletePending', 'DeleteComplete')]
    [string] $Status,

    [ValidateSet('Snapshot', 'Desired')]
    [string] $Source = 'Snapshot',

    [string] $Text,

    [ValidateSet('Inbound', 'Outbound')]
    [string[]] $Direction,

    [ValidateSet('Allow', 'Block')]
    [string[]] $Action,

    [switch] $Enabled,

    [switch] $Disabled,

    [string[]] $Profile,

    [string] $NamePattern,

    [string] $Program,

    [string] $Service,

    [string] $Protocol,

    [string[]] $LocalPort,

    [string[]] $RemotePort,

    [string] $LocalAddress,

    [string] $RemoteAddress,

    [string] $Sid,

    [switch] $MissingProgram
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('Command')) {
    Get-Help -Name $PSCommandPath -Full | Out-String -Width 120 | Write-Output
    return
}

$modulePath = Join-Path $PSScriptRoot 'src\PSNetRules.psm1'
Import-Module -Name $modulePath -Force -ErrorAction Stop

try {
    if ($WhatIfPreference -and $Command -notin @('adopt', 'unmanage', 'generate')) {
        throw '-WhatIf is supported only by adopt, unmanage, and generate.'
    }
    if ($Force -and $Command -ne 'generate') {
        throw '-Force is supported only by generate (to overwrite an existing generated script).'
    }
    if (($New -or $Update -or $Rename) -and $Command -ne 'adopt') {
        throw '-New, -Update, and -Rename are supported only by adopt.'
    }
    if ($Nrpt -and $Command -ne 'adopt') {
        throw '-Nrpt is supported only by adopt.'
    }
    if ($PSBoundParameters.ContainsKey('Name') -and $Command -notin @('adopt', 'unmanage')) {
        throw '-Name is supported only by adopt and unmanage.'
    }
    if ($Command -eq 'unmanage' -and (-not $PSBoundParameters.ContainsKey('Name') -or $null -eq $Name -or $Name.Count -eq 0)) {
        throw 'unmanage requires -Name.'
    }
    if (($OutputPath) -and $Command -ne 'generate') {
        throw '-OutputPath is supported only by generate.'
    }
    if ($Status -and $Command -ne 'diff') {
        throw '-Status is supported only by diff.'
    }
    $searchOnlyParameters = @('Source', 'Text', 'Direction', 'Action', 'Enabled', 'Disabled', 'Profile', 'NamePattern', 'Program', 'Service', 'Protocol', 'LocalPort', 'RemotePort', 'LocalAddress', 'RemoteAddress', 'Sid', 'MissingProgram')
    foreach ($searchParameter in $searchOnlyParameters) {
        if ($PSBoundParameters.ContainsKey($searchParameter) -and $Command -ne 'search') {
            throw ('-{0} is supported only by search.' -f $searchParameter)
        }
    }

    switch ($Command) {
        'capture'  { Invoke-NRCapture -Path $Path }
        'diff'     { Invoke-NRDiff -Path $Path -Status $Status }
        'validate' { Invoke-NRValidate -Path $Path }
        'adopt' {
            $operationParameters = @{ Path = $Path; New = $New; Update = $Update; Rename = $Rename; Nrpt = $Nrpt; Name = $Name; WhatIf = $WhatIfPreference }
            if ($PSBoundParameters.ContainsKey('Confirm')) { $operationParameters['Confirm'] = $Confirm }
            Invoke-NRAdopt @operationParameters
        }
        'unmanage' {
            $operationParameters = @{ Path = $Path; Name = $Name; WhatIf = $WhatIfPreference }
            if ($PSBoundParameters.ContainsKey('Confirm')) { $operationParameters['Confirm'] = $Confirm }
            Invoke-NRUnmanage @operationParameters
        }
        'generate' {
            $operationParameters = @{ Path = $Path; OutputPath = $OutputPath; Force = $Force; WhatIf = $WhatIfPreference }
            if ($PSBoundParameters.ContainsKey('Confirm')) { $operationParameters['Confirm'] = $Confirm }
            Invoke-NRGenerate @operationParameters
        }
        'search' {
            $operationParameters = @{
                Path = $Path; Source = $Source; Text = $Text; Direction = $Direction; Action = $Action
                Enabled = $Enabled; Disabled = $Disabled; Profile = $Profile; NamePattern = $NamePattern
                Program = $Program; Service = $Service; Protocol = $Protocol; LocalPort = $LocalPort
                RemotePort = $RemotePort; LocalAddress = $LocalAddress; RemoteAddress = $RemoteAddress
                Sid = $Sid; MissingProgram = $MissingProgram
            }
            Invoke-NRSearch @operationParameters
        }
    }
}
catch {
    [Console]::Error.WriteLine(('PSNetRules: {0}' -f $_.Exception.Message))
    exit 1
}
