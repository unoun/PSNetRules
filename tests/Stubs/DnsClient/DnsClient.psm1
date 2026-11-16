# Stub DnsClient for non-Windows unit-test use only: defines cmdlet signatures so Pester can mock them.
function Get-DnsClientNrptRule {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$Name,[string]$Namespace)
  throw 'stub must be mocked'
}
function Add-DnsClientNrptRule {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param(
    [object]$Namespace,[object]$IPsecTrustAuthority,[object]$DANameServers,[object]$DAEnable,[object]$DAIPsecEncryptionType,[object]$DAIPsecRequired,[object]$DAProxyServerName,[object]$DAProxyType,[object]$NameServers,[object]$NameEncoding,[object]$DnsSecEnable,[object]$DnsSecIPsecEncryptionType,[object]$DnsSecIPsecRequired,[object]$DnsSecValidationRequired,[object]$DisplayName,[object]$Comment,[switch]$PassThru
  )
}
function Remove-DnsClientNrptRule {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param([string]$Name,[switch]$Force)
}
function Set-DnsClientNrptRule {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param(
    [string]$Name,[object]$Namespace,[object]$IPsecTrustAuthority,[object]$DANameServers,[object]$DAEnable,[object]$DAIPsecEncryptionType,[object]$DAIPsecRequired,[object]$DAProxyServerName,[object]$DAProxyType,[object]$NameServers,[object]$NameEncoding,[object]$DnsSecEnable,[object]$DnsSecIPsecEncryptionType,[object]$DnsSecIPsecRequired,[object]$DnsSecValidationRequired,[object]$DisplayName,[object]$Comment,[switch]$PassThru
  )
}
Export-ModuleMember -Function *
