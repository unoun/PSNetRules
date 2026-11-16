#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(0, 100)]
    [int] $CoverageTarget = 99
)

$ErrorActionPreference = 'Stop'
Import-Module Pester -MinimumVersion 6.0.0 -DisableNameChecking -ErrorAction Stop

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$coverageDirectory = Join-Path $repositoryRoot 'coverage'
if (-not (Test-Path -LiteralPath $coverageDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $coverageDirectory -Force | Out-Null
}

# The Windows-only test file requires real CimInstance objects and the
# Windows security principal. It belongs to the unit suite so the module
# lines it covers stay inside the coverage gate below, but it is only
# included on Windows; its Describe blocks also skip themselves elsewhere.
$testPaths = @((Join-Path $PSScriptRoot 'PSNetRules.Tests.ps1'))
if ($env:OS -eq 'Windows_NT') {
    $testPaths += Join-Path $PSScriptRoot 'PSNetRules.Windows.Tests.ps1'
}
else {
    Write-Information 'Non-Windows platform: PSNetRules.Windows.Tests.ps1 is excluded from this run.' -InformationAction Continue
}

$config = New-PesterConfiguration
$config.Run.Path = $testPaths
$config.Run.Exit = $true
$config.Should.DisableV5 = $true
$config.Output.Verbosity = 'Detailed'
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = Join-Path $repositoryRoot 'src\PSNetRules.psm1'
$config.CodeCoverage.CoveragePercentTarget = $CoverageTarget
$config.CodeCoverage.OutputPath = Join-Path $coverageDirectory 'unit-coverage.xml'

Invoke-Pester -Configuration $config
