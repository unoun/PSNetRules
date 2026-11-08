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

$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'PSNetRules.Tests.ps1'
$config.Run.Exit = $true
$config.Should.DisableV5 = $true
$config.Output.Verbosity = 'Detailed'
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = Join-Path $repositoryRoot 'src\PSNetRules.psm1'
$config.CodeCoverage.CoveragePercentTarget = $CoverageTarget
$config.CodeCoverage.OutputPath = Join-Path $coverageDirectory 'unit-coverage.xml'

Invoke-Pester -Configuration $config
