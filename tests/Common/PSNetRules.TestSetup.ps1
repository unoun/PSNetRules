# Shared setup for the PSNetRules unit test files.
#
# Dot-source this file from the root BeforeAll of each unit test file:
#
#     BeforeAll {
#         . (Join-Path $PSScriptRoot 'Common\PSNetRules.TestSetup.ps1')
#     }
#
# It loads the cmdlet modules (real ones on Windows, signature-only stubs
# elsewhere), imports exactly one instance of the module under test, loads
# the shared fixtures, and defines the helper functions the tests use.
# Everything is resolved relative to this file's location under tests\, so
# the same setup works from any repository or sandbox copy of the tree.

# Repository layout, derived from this file's own location (tests\Common),
# never from the caller's $PSScriptRoot: dot-sourcing changes what
# $PSScriptRoot means, and a mutation-testing sandbox copies this tree to a
# different root where the same relative layout must still resolve.
$script:NRTestsRoot = Split-Path -Parent $PSScriptRoot
$script:NRRepositoryRoot = Split-Path -Parent $script:NRTestsRoot

# Load the Windows cmdlet modules the unit tests mock. On Windows the real
# NetSecurity and DnsClient modules are used. On other platforms they do not
# exist, so fall back to the signature-only stubs under tests\Stubs, imported
# by path so they can never shadow a real module through PSModulePath. A
# failure on Windows is rethrown: a missing real module there is a genuine
# environment error, not something a stub should paper over.
foreach ($moduleName in @('NetSecurity', 'DnsClient')) {
    try {
        Import-Module $moduleName -ErrorAction Stop
    }
    catch {
        if ($env:OS -eq 'Windows_NT') { throw }
        $stubPath = Join-Path $script:NRTestsRoot ('Stubs\{0}\{0}.psd1' -f $moduleName)
        Import-Module $stubPath -Force -ErrorAction Stop
    }
}

# Mock -ModuleName must resolve to one unambiguous module instance. Remove
# any previously loaded copy before importing the module under test.
Get-Module -Name PSNetRules | Remove-Module -Force -ErrorAction SilentlyContinue
$netRulesModulePath = [System.IO.Path]::GetFullPath((Join-Path $script:NRRepositoryRoot 'src\PSNetRules.psm1'))
$script:NetRulesModule = Import-Module -Name $netRulesModulePath -Force -PassThru -ErrorAction Stop

$fixturePath = Join-Path $script:NRTestsRoot 'Fixtures\PSNetRules.TestFixtures.ps1'
if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) { throw "Shared test fixture file not found: $fixturePath" }
. $fixturePath

$loadedNetRulesModules = @(Get-Module -Name PSNetRules)
if ($loadedNetRulesModules.Count -ne 1 -or $loadedNetRulesModules[0].Path -ne $script:NetRulesModule.Path) {
    throw ('Expected exactly one PSNetRules module instance from {0}; found {1}.' -f $netRulesModulePath, $loadedNetRulesModules.Count)
}

function Invoke-NRPrivateFunction {
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

$script:PSNetRulesRootScriptPath = [System.IO.Path]::GetFullPath((Join-Path $script:NRRepositoryRoot 'PSNetRules.ps1'))

function Invoke-NRRootScriptInChildProcess {
    [CmdletBinding()]
    param(
        [string[]] $Arguments = @(),
        [string] $ScriptPath = $script:PSNetRulesRootScriptPath
    )

    # Run the CLI in a child process using the same PowerShell executable.
    # Bind parameters by name so switches such as -WhatIf are not mistaken
    # for positional values of the CLI's Path parameter.
    $executablePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    $payloadJson = ConvertTo-Json -InputObject ([pscustomobject]@{
        ScriptPath = $ScriptPath
        Arguments = @($Arguments)
    }) -Depth 4 -Compress
    $payloadBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
    $childCommandTemplate = @'
$ProgressPreference = 'SilentlyContinue'
$payloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('__PAYLOAD__'))
$payload = ConvertFrom-Json -InputObject $payloadJson
$arguments = @($payload.Arguments | ForEach-Object { [string]$_ })

# The PowerShell parameter binder handles -? before the CLI script body runs.
if ($arguments.Count -eq 1 -and $arguments[0] -eq '-?') {
& $payload.ScriptPath -?
return
}

$invokeParameters = @{}
$argumentIndex = 0
if ($arguments.Count -gt 0 -and -not $arguments[0].StartsWith('-')) {
$invokeParameters['Command'] = $arguments[0]
$argumentIndex = 1
}

$switchParameterNames = @('Force', 'New', 'Update', 'Rename', 'WhatIf', 'Confirm', 'Enabled', 'Disabled', 'MissingProgram', 'Nrpt')
$valueParameterNames = @('Command', 'Path', 'Name', 'OutputPath', 'Status', 'Source', 'Text', 'Direction', 'Action', 'Profile', 'NamePattern', 'Program', 'Service', 'Protocol', 'LocalPort', 'RemotePort', 'LocalAddress', 'RemoteAddress', 'Sid')
while ($argumentIndex -lt $arguments.Count) {
$token = $arguments[$argumentIndex]
if (-not $token.StartsWith('-')) {
    throw ('Unexpected positional argument: {0}' -f $token)
}

$parameterName = $token.TrimStart('-')
if ($switchParameterNames -contains $parameterName) {
    $invokeParameters[$parameterName] = $true
    $argumentIndex++
    continue
}
if ($valueParameterNames -notcontains $parameterName) {
    throw ('Unsupported test argument: {0}' -f $token)
}

$argumentIndex++
if ($argumentIndex -ge $arguments.Count -or $arguments[$argumentIndex].StartsWith('-')) {
    throw ('Missing value for parameter -{0}.' -f $parameterName)
}

if ($parameterName -eq 'Name') {
    $nameValues = New-Object 'System.Collections.Generic.List[string]'
    while ($argumentIndex -lt $arguments.Count -and -not $arguments[$argumentIndex].StartsWith('-')) {
        $nameValues.Add([string]$arguments[$argumentIndex])
        $argumentIndex++
    }
    $invokeParameters[$parameterName] = $nameValues.ToArray()
}
else {
    $invokeParameters[$parameterName] = [string]$arguments[$argumentIndex]
    $argumentIndex++
}
}

if ($invokeParameters.Count -eq 0) {
& $payload.ScriptPath
}
else {
& $payload.ScriptPath @invokeParameters
}
'@
    $childCommand = $childCommandTemplate.Replace('__PAYLOAD__', $payloadBase64)
    $encodedCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($childCommand))

    $process = New-Object System.Diagnostics.Process
    try {
        $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
        $process.StartInfo.FileName = $executablePath
        $process.StartInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encodedCommand
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true

        if (-not $process.Start()) {
            throw 'Unable to start the PowerShell child process.'
        }

        # Read stdout and stderr concurrently so a full pipe cannot block
        # the child process while the parent waits for the other stream.
        $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
        $standardErrorTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $standardOutput = $standardOutputTask.Result
        $standardError = $standardErrorTask.Result
        $outputParts = @($standardOutput, $standardError) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StandardOutput = $standardOutput
            StandardError = $standardError
            Output = $outputParts -join [Environment]::NewLine
        }
    }
    finally {
        $process.Dispose()
    }
}

function Assert-NRChildProcessSuccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object] $Result,
        [Parameter(Mandatory = $true)] [string] $Context
    )
    if ($Result.ExitCode -ne 0) {
        throw ("{0} failed with exit code {1}.`nStandardOutput:`n{2}`nStandardError:`n{3}" -f `
            $Context, $Result.ExitCode, $Result.StandardOutput, $Result.StandardError)
    }
}

function Copy-TestObject {
    param([object] $InputObject)
    return ($InputObject | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
}

function Write-TestUtf8JsonFile {
    param([string] $Path, [object] $InputObject)
    $json = ConvertTo-Json -InputObject $InputObject -Depth 100
    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $json, $encoding)
}

# Define shared helpers in the root BeforeAll scope. Pester's isolated It
# scopes do not reliably expose functions declared inside a Describe block.
function Get-NRTestUnmanageBackups {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string] $ConfigurationPath)

    $directory = Join-Path (Split-Path -Parent $ConfigurationPath) 'backups'
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { return @() }
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($ConfigurationPath)
    $extension = [System.IO.Path]::GetExtension($ConfigurationPath)
    return @(Get-ChildItem -LiteralPath $directory -Filter ($baseName + '*.pre-unmanage.*' + $extension) -File)
}
