# PSNetRules

PSNetRules is a Windows PowerShell 5.1 CLI for capturing, reviewing, validating, and generating changes to local Windows Firewall and DNS Client NRPT configuration. Run `.\PSNetRules.ps1` without a command to display command help.

## Scope

PSNetRules manages these local resources:

- Firewall Rules in `PersistentStore`, including each Rule and its seven associated Filter types.
- Firewall Dynamic Keyword Addresses in `PersistentStore`.
- The `Domain`, `Private`, and `Public` Firewall Profiles in `PersistentStore`.
- Local NRPT rules returned by `Get-DnsClientNrptRule`.

It does not manage GPO policy, `ActiveStore` as a whole, IPsec rule sets, DNS client/server interface settings, static routes, QoS, or Port Proxy.

## Management model

Firewall Rules are managed selectively. The other three resource collections—Firewall Profiles, Dynamic Keyword Addresses, and NRPT Rules—use whole-collection desired state.

During `capture`, PSNetRules records all current `PersistentStore` Firewall Rules in the Snapshot and builds a comparison inventory against `SystemDefaults`:

- A current Rule whose Name also exists in `SystemDefaults` and whose comparable Rule and Filter properties match exactly is `DefaultExcluded`. It is not adopted automatically.
- A Rule without an exact same-Name match is a `NewCandidate`. Review it with `diff` and explicitly adopt it when it should be managed.
- An inconclusive comparison is reported as `ComparisonInconclusive`; it is not treated as a confirmed default match.
- An adopted Rule remains managed even if it later becomes identical to a `SystemDefaults` Rule.
- Rules recorded in `excludedFirewallRules` remain excluded from management and are not deleted by a generated plan.

The comparison covers the Rule and its seven Filter objects. Identity, PolicyStore provenance, and runtime-status metadata are excluded from the comparison. The Snapshot stores each normalized comparison property as a `Value` field; complex-value canonicalization is performed only when required during comparison. Snapshot and State sidecars use schema version 1. Snapshot comparison fields do not store precomputed `Canonical` strings.

## Files

For a desired-state file named `network-rules.json`, PSNetRules maintains these related files in the same directory:

| File | Purpose |
|---|---|
| `network-rules.json` | Desired state. `firewallRules` contains adopted Rules; `excludedFirewallRules` records Rules explicitly excluded from management. Profiles, Dynamic Keyword Addresses, and NRPT Rules represent their complete desired local collections. |
| `network-rules.snapshot.json` | Latest captured local configuration and the `PersistentStore` / `SystemDefaults` comparison inventories used to classify Firewall Rules. |
| `network-rules.state.json` | Adopted Firewall Rule Names and the mapping from each NRPT logical ID to its Windows-generated Name. |
| `backups/` | Backups created before `adopt`, `unmanage`, and generated-plan execution. |

The example configuration and JSON Schemas are in `examples/` and `schema/`. `network-rules.schema.json`, `snapshot.schema.json`, and `state.schema.json` describe the Desired Configuration and the two sidecar files respectively.

## Requirements

- Windows with the inbox `NetSecurity` and `DnsClient` PowerShell modules.
- Windows PowerShell 5.1 for the CLI and generated scripts.
- Administrator privileges for `capture` and for executing a generated change script.
- Pester 6.x for the Pester suites.

`diff`, `validate`, `adopt`, `unmanage`, `generate`, and `search` do not require elevation. `diff` reads the saved Snapshot; it does not query Windows. Run `capture` after the local configuration may have changed.

## Initial setup

From the repository root, run the following in an elevated Windows PowerShell 5.1 session:

```powershell
.\PSNetRules.ps1 capture
```

On the first capture, PSNetRules creates `network-rules.json` with an empty `firewallRules` collection, while capturing the current Profiles, Dynamic Keyword Addresses, NRPT Rules, and all `PersistentStore` Firewall Rules into the Snapshot. It also creates the State sidecar.

Review the candidates, then adopt the Rules that should be managed:

```powershell
.\PSNetRules.ps1 diff
.\PSNetRules.ps1 adopt -New -WhatIf
.\PSNetRules.ps1 adopt -New
.\PSNetRules.ps1 validate
```

`capture` refreshes the Snapshot and managed-name inventory. It does not overwrite an existing desired-state file.

## Routine workflow

### Capture and review

```powershell
# Refresh the local capture (run elevated).
.\PSNetRules.ps1 capture

# Review all Firewall classifications and other managed resources.
.\PSNetRules.ps1 diff

# Narrow the output to a Firewall classification.
.\PSNetRules.ps1 diff -Status NewCandidate
.\PSNetRules.ps1 diff -Status Rename
```

`-Status` filters Firewall Rule classifications. When it is supplied, `diff` does not display the non-Firewall collection comparison.

The main Firewall Rule statuses are:

| Status | Meaning |
|---|---|
| `NewCandidate` | Current unmanaged Rule without an exact same-Name `SystemDefaults` match. |
| `DefaultExcluded` | Current unmanaged Rule that exactly matches a same-Name `SystemDefaults` Rule. |
| `ComparisonInconclusive` | The available comparison data cannot establish an exact match. |
| `InSync` / `Modified` | Adopted Rule matches / differs from the latest capture. |
| `Missing` | Adopted Rule is absent from the latest capture. |
| `Rename` | A `Missing` Rule and a `NewCandidate` have an unambiguous one-to-one match after ignoring Name. |
| `DeletePending` / `DeleteComplete` | An adopted Name was removed from desired state; the Rule is still present / is already absent in the latest capture. |
| `Excluded` / `ExcludedMissing` | An explicitly excluded Rule is present / absent in the latest capture. |

### Search Rules

`search` finds Firewall Rules in the latest capture Snapshot (default) or in the desired-state file (`-Source Desired`). Conditions combine with AND; repeated values of one parameter combine with OR. Substring matches are case-insensitive.

```powershell
# Inbound Allow Rules in the Snapshot.
.\PSNetRules.ps1 search -Direction Inbound -Action Allow

# Rules whose security filters mention a SID, in the desired state.
.\PSNetRules.ps1 search -Source Desired -Sid S-1-5-18

# Substring match across every field.
.\PSNetRules.ps1 search -Text sql

# Rules whose Program file no longer exists on this computer.
.\PSNetRules.ps1 search -MissingProgram
```

With `-MissingProgram`, Rules whose Program is blank or `Any` are skipped. Paths that cannot be verified (relative paths, paths containing `%`, or access errors) are reported as `Unverifiable` instead of `Missing`; environment variables are not expanded. The full specification is in `docs/search-command-spec.md`.

### Adopt or update Rules

```powershell
# Preview and adopt all NewCandidate Rules.
.\PSNetRules.ps1 adopt -New -WhatIf
.\PSNetRules.ps1 adopt -New

# Adopt one or more selected candidates.
.\PSNetRules.ps1 adopt -Name 'Rule-Name'

# Replace an adopted Rule's desired settings with its latest captured settings.
.\PSNetRules.ps1 adopt -Update -Name 'Rule-Name'

# Review and accept detected name-only replacements.
.\PSNetRules.ps1 adopt -Rename -WhatIf
.\PSNetRules.ps1 adopt -Rename
.\PSNetRules.ps1 adopt -Rename -Name 'Old-Rule-Name'
```

`adopt` changes the desired-state and State files, not Windows Firewall. It displays the selected Rules, supports `-WhatIf` and confirmation, and creates file backups before writing. `-Rename -Name` takes the old Name shown by `diff`. Rename detection is limited to unique one-to-one matches; ambiguous matches remain `Missing` and `NewCandidate`.

### Stop managing Rules without deleting them

Use `unmanage` when a Rule must remain in Windows but should no longer be controlled by PSNetRules:

```powershell
.\PSNetRules.ps1 unmanage -Name 'Rule-Name' -WhatIf
.\PSNetRules.ps1 unmanage -Name 'Rule-Name'
.\PSNetRules.ps1 unmanage -Name 'Rule-A', 'Rule-B'
```

`unmanage` removes the selected Names from `firewallRules` and the managed-name inventory, then records them in `excludedFirewallRules`. It can resolve a Name from desired state, the managed inventory, the latest Snapshot, or the exclusion list. All requested Names are validated before any file is changed. The command stages both replacement files, creates backups, and attempts to restore the originals if the commit fails. It does not change Windows Firewall or the Snapshot.

A present excluded Rule is reported as `Excluded`; if it later disappears, its exclusion remains recorded as `ExcludedMissing`. Excluded Rules do not return as `NewCandidate` and are not deleted by `generate`. To resume managing a current Rule, use `adopt -Name 'Rule-Name'`.

Do not remove a Rule only from `firewallRules` when the intent is to leave it in Windows but stop managing it. Removing an adopted Rule from desired state while leaving its Name in the State inventory intentionally marks it `DeletePending`; `generate` will emit a removal command for it. Use `unmanage` for an exclusion.

### Validate, generate, and apply

```powershell
# Validate the desired-state file.
.\PSNetRules.ps1 validate

# Generate a reviewable script (default: network-rules.generate.ps1).
.\PSNetRules.ps1 generate

# Review the generated commands in an elevated session.
.\network-rules.generate.ps1 -WhatIf

# Execute only after reviewing the plan and its targets.
.\network-rules.generate.ps1

# Capture again and verify the resulting state.
.\PSNetRules.ps1 capture
.\PSNetRules.ps1 diff
```

`generate` only writes a PowerShell script; it does not change Windows settings. Use `-OutputPath` to choose another output file and `-Force` to overwrite an existing generated script.

The generated script:

- Requires Windows PowerShell 5.1 and an elevated administrator token.
- Is bound to the generating computer and the SHA-256 hashes of the module, desired configuration, Snapshot, and State files.
- Rechecks the live local configuration and the `PersistentStore` / `SystemDefaults` comparison inventories before applying changes.
- Creates backups of the configuration, Snapshot, and State before execution.
- Requires the exact confirmation phrase `EXECUTE GENERATED PLAN` before making changes.
- Uses `-WhatIf` for mutating cmdlets that support it. `Update-NetFirewallDynamicKeywordAddress` does not support `-WhatIf`; in preview mode the generated script prints the exact command instead of invoking it.
- Reconciles Firewall Rules only when they are in the managed inventory or desired state and are not explicitly excluded. Unmanaged Rules are left untouched.

The generated operation is not transactional. If a Windows cmdlet fails after earlier commands have succeeded, Windows may be left partially changed. The pre-execution backups are available for recovery and reconciliation.

## Tests and quality checks

The test suites separate module behavior, Windows cmdlet contracts, and real system integration:

- **Unit** (`tests/`): Pester tests for module behavior and the `PSNetRules.ps1` entry point. Windows cmdlets are mocked at the OS boundary. The Unit runner targets 99% module line coverage by default.
  - `PSNetRules.Tests.ps1` is platform-independent and also runs under PowerShell 7 on non-Windows platforms: the shared setup in `tests/Common/` falls back to the signature-only stub modules under `tests/Stubs/` when the real `NetSecurity` and `DnsClient` modules do not exist. On Windows the real modules are always used, and a failure to load them is an error.
  - `PSNetRules.Windows.Tests.ps1` holds the few tests that require real Windows objects (a `CimInstance`, the Windows security principal). It is part of the unit suite so those module lines stay inside the coverage gate; the runner includes it only on Windows, and its tests skip themselves on other platforms.
- **Contract** (`contract-tests/`): elevated, read-only checks against installed Windows cmdlet parameters and real native objects.
- **Integration** (`integration-tests/`): guarded create/update/delete tests for temporary Firewall Rules, local NRPT Rules, and Dynamic Keyword Addresses. Firewall Profiles are read-only in this suite. No system changes occur unless `-AllowSystemChanges` is supplied and the confirmation phrase is accepted.
- **PSScriptAnalyzer**: static PowerShell lint checks.
- **PSComplexity**: static complexity checks for function maintainability.

Unit tests are run first, then Contract tests, then Integration tests. PSScriptAnalyzer and PSComplexity are independent static quality gates and must also pass.

```powershell
# Unit tests (Windows PowerShell 5.1 or PowerShell 7).
powershell.exe -NoProfile -File .\tests\Run-UnitTests.ps1
pwsh.exe -NoProfile -File .\tests\Run-UnitTests.ps1

# Contract tests (elevated; run only after Unit tests pass).
powershell.exe -NoProfile -File .\contract-tests\Run-ContractTests.ps1

# Integration tests (elevated; preview only unless explicitly authorized).
powershell.exe -NoProfile -File .\integration-tests\Run-IntegrationTests.ps1
```

The Integration runner defaults to a read-only preview. To authorize its temporary Firewall Rule, NRPT Rule, and Dynamic Keyword Address create/update/delete checks, run it with `-AllowSystemChanges` and enter the exact confirmation phrase shown by the runner. Use this only on a machine where those temporary local changes are acceptable.

The coverage percentage measures executed code in `src/PSNetRules.psm1`; it does not measure assertion strength or mutation score. The root CLI is invoked in child PowerShell processes, so its child-process lines are not part of the module coverage percentage.

## Performance tests

The opt-in performance harness measures the Capture post-enumeration work and the Diff in-memory pipeline using a fixed synthetic workload. It does not query or modify the machine's Firewall or NRPT configuration. It is separate from the correctness gates.

```powershell
# Print the stage breakdown using the default three measured iterations.
.\performance-tests\Measure-PSNetRulesPerformance.ps1

# Establish a reviewed baseline explicitly (the file must not already exist).
.\performance-tests\Measure-PSNetRulesPerformance.ps1 `
    -Mode InitializeBaseline `
    -BaselinePath '.\performance-tests\PerformanceBaseline.json'

# Fail when any measured metric is at least 5% slower than the baseline.
.\performance-tests\Measure-PSNetRulesPerformance.ps1 `
    -Mode Test `
    -BaselinePath '.\performance-tests\PerformanceBaseline.json'
```

Use the same machine, PowerShell host, workload, iteration count, and warm-up count for baseline and test runs. See [performance test details](performance-tests/README.md) for measured stages, baseline requirements, and report output.

## Windows Firewall rule model

For the relationship between Rule properties, Filters, Direction, Local/Remote, Profile, Application/Service, rule precedence, and default actions, see [Windows Firewall Rule の構造と通信判定](docs/windows-firewall-rule-model.md).
