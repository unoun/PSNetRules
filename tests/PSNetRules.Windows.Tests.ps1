BeforeAll {
    . (Join-Path $PSScriptRoot 'Common\PSNetRules.TestSetup.ps1')
}

# Tests in this file require real Windows objects: a CimInstance from
# CimCmdlets and the Windows security principal. They are part of the unit
# suite (so the module lines they cover stay inside the unit coverage gate),
# but they can only run on Windows. The unit test runner excludes this file
# on other platforms, and every Describe below also skips itself there, so a
# direct Invoke-Pester over tests/ stays green off Windows as well.

Describe 'PSNetRules managed Firewall Rule workflows' -Skip:($env:OS -ne 'Windows_NT') {
    It 'projects normalized comparison properties from a CimInstance as Value-only fields' {
        $cimRule = New-CimInstance -Namespace 'root/standardcimv2' -ClassName 'MSFT_NetFirewallRule' -ClientOnly `
            -Property @{ Name = 'Cim-Rule'; InstanceID = 'cim-rule-id'; DisplayName = 'CIM Rule' }
        $cimFields = Invoke-NRPrivateFunction -Name Get-NRComparisonProperties -Parameters @{ InputObject = $cimRule; Section = 'Rule' }
        $cimFields.Count | Should-Be 1
        $cimFields['Rule.DisplayName'].Value | Should-Be 'CIM Rule'
        $cimFields['Rule.DisplayName'].PSObject.Properties['Canonical'] | Should-Be $null
    }
}

Describe 'PSNetRules uncovered branch regression coverage' -Skip:($env:OS -ne 'Windows_NT') {
    It 'converts a CimInstance to a plain comparison value' {
        $nativeRule = New-NRFixtureCimFirewallRule -Name 'CimConversionRule' -InstanceId 'cim-conversion-id'
        $cimValue = Invoke-NRPrivateFunction -Name ConvertTo-NRComparisonPlainValue -Parameters @{ Value = $nativeRule }
        $cimValue.Name | Should-Be 'CimConversionRule'
        $cimValue.InstanceID | Should-Be 'cim-conversion-id'
    }

    It 'evaluates the current Windows administrator identity without requiring elevation' {
        $result = Invoke-NRPrivateFunction -Name Test-NRIsAdministrator
        ($result -is [bool]) | Should-Be $true
    }
}
