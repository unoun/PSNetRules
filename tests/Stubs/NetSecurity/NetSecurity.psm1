# Stub NetSecurity for Linux unit-test use only: defines cmdlet signatures so Pester can mock them.
function Get-NetFirewallRule {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[string[]]$Name,[string]$DisplayName,[object]$AssociatedNetFirewallRule)
  throw 'NetSecurity stub: Get-NetFirewallRule must be mocked in unit tests.'
}
function Get-NetFirewallAddressFilter {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[object]$AssociatedNetFirewallRule)
  throw 'stub must be mocked'
}
function Get-NetFirewallApplicationFilter {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[object]$AssociatedNetFirewallRule)
  throw 'stub must be mocked'
}
function Get-NetFirewallPortFilter {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[object]$AssociatedNetFirewallRule)
  throw 'stub must be mocked'
}
function Get-NetFirewallServiceFilter {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[object]$AssociatedNetFirewallRule)
  throw 'stub must be mocked'
}
function Get-NetFirewallInterfaceFilter {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[object]$AssociatedNetFirewallRule)
  throw 'stub must be mocked'
}
function Get-NetFirewallInterfaceTypeFilter {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[object]$AssociatedNetFirewallRule)
  throw 'stub must be mocked'
}
function Get-NetFirewallSecurityFilter {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[object]$AssociatedNetFirewallRule)
  throw 'stub must be mocked'
}
function Get-NetFirewallProfile {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[string[]]$Name,[switch]$All)
  throw 'stub must be mocked'
}
function Get-NetFirewallDynamicKeywordAddress {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding()]
  param([string]$PolicyStore,[switch]$All,[string]$Id)
  throw 'stub must be mocked'
}
function New-NetFirewallRule {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'The real cmdlet has a -Profile parameter; the stub must declare the same name for mock parameter binding.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param(
    [string]$Name,[string]$PolicyStore,[object]$DisplayName,[object]$Description,[object]$Group,[object]$Enabled,[object]$Profile,[object]$Platform,[object]$Direction,[object]$Action,[object]$EdgeTraversalPolicy,[object]$LooseSourceMapping,[object]$LocalOnlyMapping,[object]$Owner,[object]$RemoteDynamicKeywordAddresses,
    [object]$LocalAddress,[object]$RemoteAddress,[object]$Protocol,[object]$LocalPort,[object]$RemotePort,[object]$IcmpType,[object]$DynamicTarget,[object]$Program,[object]$Package,[object]$Service,[object]$InterfaceAlias,[object]$InterfaceType,[object]$LocalUser,[object]$RemoteUser,[object]$RemoteMachine,[object]$Authentication,[object]$Encryption,[object]$OverrideBlockRules
  )
}
function Set-NetFirewallRule {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'The real cmdlet has a -Profile parameter; the stub must declare the same name for mock parameter binding.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param(
    [string[]]$Name,[string]$PolicyStore,[object]$NewDisplayName,[object]$DisplayName,[object]$Description,[object]$Group,[object]$Enabled,[object]$Profile,[object]$Platform,[object]$Direction,[object]$Action,[object]$EdgeTraversalPolicy,[object]$LooseSourceMapping,[object]$LocalOnlyMapping,[object]$Owner,[object]$RemoteDynamicKeywordAddresses,
    [object]$LocalAddress,[object]$RemoteAddress,[object]$Protocol,[object]$LocalPort,[object]$RemotePort,[object]$IcmpType,[object]$DynamicTarget,[object]$Program,[object]$Package,[object]$Service,[object]$InterfaceAlias,[object]$InterfaceType,[object]$LocalUser,[object]$RemoteUser,[object]$RemoteMachine,[object]$Authentication,[object]$Encryption,[object]$OverrideBlockRules
  )
}
function Remove-NetFirewallRule {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param([string[]]$Name,[string]$PolicyStore)
}
function New-NetFirewallDynamicKeywordAddress {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param([string]$Id,[object]$Keyword,[object]$Addresses,[object]$AutoResolve,[string]$PolicyStore)
}
function Update-NetFirewallDynamicKeywordAddress {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param([string]$Id,[object]$Addresses,[object]$Append,[string]$PolicyStore)
}
function Remove-NetFirewallDynamicKeywordAddress {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param([string]$Id,[string]$PolicyStore)
}
function Set-NetFirewallProfile {
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Signature-only stub: parameters mirror the real cmdlet so Pester can mock it and bind ParameterFilter checks; bodies only throw or return nothing.')]
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param(
    [string[]]$Name,[string]$PolicyStore,[object]$Enabled,[object]$DefaultInboundAction,[object]$DefaultOutboundAction,[object]$AllowInboundRules,[object]$AllowLocalFirewallRules,[object]$AllowLocalIPsecRules,[object]$AllowUserApps,[object]$AllowUserPorts,[object]$AllowUnicastResponseToMulticast,[object]$NotifyOnListen,[object]$EnableStealthModeForIPsec,[object]$LogFileName,[object]$LogMaxSizeKilobytes,[object]$LogAllowed,[object]$LogBlocked,[object]$LogIgnored,[object]$DisabledInterfaceAliases
  )
}
Export-ModuleMember -Function *
