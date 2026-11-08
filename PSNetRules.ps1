<#
.SYNOPSIS
Capture, review, validate, adopt, unmanage, and generate changes for local Windows Firewall and DNS NRPT configuration.

.DESCRIPTION
PSNetRules uses a desired-state workflow. Capture records the current local configuration and a Firewall Rule comparison Snapshot. Review differences, explicitly select the Firewall Rules to manage, and generate a PowerShell script for applying reviewed changes.
Run without a command to display this help.

.PARAMETER Command
Operation to perform: capture, diff, validate, adopt, unmanage, or generate.

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

.PARAMETER Name
For adopt, select Firewall Rule Names to adopt, or to update when used with -Update. With -Rename, specify old Names. For unmanage, exclude the named Rules from management without changing Windows Firewall.

.PARAMETER OutputPath
Output file for the generated PowerShell script. Valid only with generate. Defaults to a .generate.ps1 file beside the desired-state file.

.PARAMETER Status
Filter diff output to one Firewall Rule classification status, such as NewCandidate, Modified, Rename, or Excluded. Valid only with diff.

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
.\PSNetRules.ps1 unmanage -Name 'Rule-Name' -WhatIf
Preview excluding a Rule from management without deleting it from Windows.

.EXAMPLE
.\PSNetRules.ps1 generate -OutputPath .\network-rules.generate.ps1
Generate a reviewable PowerShell change script.

.NOTES
The generated script requires an elevated Windows PowerShell 5.1 session. Review it before execution. Run Unit tests before Contract tests, and Contract tests before Integration tests.
#>
#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet('capture', 'diff', 'validate', 'adopt', 'unmanage', 'generate')]
    [string] $Command,

    [Parameter(Position = 1)]
    [string] $Path = '.\network-rules.json',

    [switch] $Force,

    [switch] $New,

    [switch] $Update,

    [switch] $Rename,

    [string[]] $Name,

    [string] $OutputPath,

    [ValidateSet('NewCandidate', 'Excluded', 'ExcludedMissing', 'DefaultExcluded', 'ComparisonInconclusive', 'InSync', 'Modified', 'Rename', 'Missing', 'DeletePending', 'DeleteComplete')]
    [string] $Status
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

    switch ($Command) {
        'capture'  { Invoke-NRCapture -Path $Path }
        'diff'     { Invoke-NRDiff -Path $Path -Status $Status }
        'validate' { Invoke-NRValidate -Path $Path }
        'adopt' {
            $operationParameters = @{ Path = $Path; New = $New; Update = $Update; Rename = $Rename; Name = $Name; WhatIf = $WhatIfPreference }
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
    }
}
catch {
    [Console]::Error.WriteLine(('PSNetRules: {0}' -f $_.Exception.Message))
    exit 1
}
