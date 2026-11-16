# Capture and Diff performance tests

The performance harness measures the CPU-intensive work performed after Capture has enumerated Windows objects and the in-memory pipeline used by Diff. It uses a fixed synthetic workload and invokes the production functions from `src/PSNetRules.psm1`.

The harness is an opt-in performance gate, separate from the correctness test suites. It does not query or modify the machine's Firewall, NRPT, desired-state, Snapshot, or State data.

## Requirements and safety

- Windows PowerShell 5.1.
- Administrator privileges are not required.
- The workload is defined by constants in the script; it is not derived from the current machine configuration or from `network-rules.json`.
- No temporary directory or temporary file is created.
- No report or baseline is written in the default `Measure` mode. A file is written only when an explicit `-OutputPath` or `-BaselinePath` is supplied.
- The parent directory of an output file must already exist. Existing files are never overwritten.
- Relative paths are resolved from the repository root and cannot escape it. Fully qualified drive-rooted and UNC paths are accepted.
- The module is loaded in memory with `New-Module`; the benchmark does not import the module from disk or use the Windows PowerShell module-analysis cache under the user profile.
- Synthetic Firewall cmdlets are provided inside the benchmark module. The measured scenario does not invoke Windows Firewall or NRPT cmdlets.

## Fixed workload

The current workload is intentionally fixed so that baseline and candidate measurements use the same data shape and classification distribution.

| Input | Count |
|---|---:|
| PersistentStore Rules | 627 |
| SystemDefaults Rules | 408 |
| Current Snapshot Rules | 627 |
| Desired / managed Rules | 220 |
| Excluded Rules | 5 |
| Managed Modified / InSync | 22 / 198 |
| Unmanaged DefaultExcluded / NewCandidate | 188 / 214 |
| Filter types per Rule | 7 |

The counts and object shapes are constants in the script. The fixture builders in `tests/Fixtures/PSNetRules.TestFixtures.ps1` are reused so synthetic native-shaped objects and desired-state records follow the same shapes as the correctness tests.

## Measure

Run from the repository root:

```powershell
.\performance-tests\Measure-PSNetRulesPerformance.ps1
```

The default mode is `Measure`, with five measured iterations and one warm-up. The warm-up matters: without it, first-run compilation and cache effects land in the first measured sample and the min/max spread within a single run can exceed 2x. Each metric is summarized by the median of its samples. The console also reports one-time synthetic-data setup, Diff-input preparation, and total benchmark elapsed time; these figures are diagnostic and are not included in the performance gate.

Use the same `-Iterations` and `-WarmupIterations` values when initializing and testing a baseline. The defaults are `5` and `1`.

## Capture metrics

Capture timings cover the in-memory work after Firewall objects have been acquired. The benchmark does not measure the time taken by Windows providers to enumerate live objects or the time to write files.

| Metric | Measurement |
|---|---|
| `Capture_InventoryProjection_PersistentStore` | Builds the PersistentStore comparison inventory from the synthetic captured Rules and retained native Filter indexes. |
| `Capture_InventoryProjection_SystemDefaults` | Builds the SystemDefaults inventory, including the Rule and seven Filter property projections. Synthetic cmdlets supply the input. |
| `Capture_InventoryValidation` | Checks inventory completeness and verifies that the PersistentStore inventory and captured configuration contain the same Rule Names. |
| `Capture_SnapshotObjectAssembly` | Assembles the schema-version-1 Snapshot object in memory. |
| `Capture_ManagedStateUpdate` | Calculates the managed Firewall Rule Name inventory without reading or writing the State sidecar. |
| `Capture_SnapshotJsonSerialization` | Serializes the Snapshot using the production JSON writer's compression settings; the JSON remains in memory. |
| `Capture_PostEnumerationTotal` | Measures the six Capture stages above together. |

All Capture stages are timed within the same scenario execution. The inventory results are reused by validation and Snapshot assembly; the benchmark does not repeat the inventory work for separate stage measurements. Serialization occurs once per measured sample and is not followed by a JSON round-trip.

## Diff metrics

Diff timings cover the in-memory pipeline. File reads, JSON parsing, and disk writes are excluded.

| Metric | Measurement |
|---|---|
| `Diff_DesiredConfigurationValidation` | Validates the synthetic desired configuration. |
| `Diff_FirewallClassification` | Runs Firewall Rule classification, including default matching and managed-object comparison. |
| `Diff_FirewallFormatting` | Formats the classification results from the same pipeline sample. |
| `Diff_NonFirewallDiffAndFormatting` | Compares and formats Firewall Profiles, Dynamic Keyword Addresses, and NRPT Rules. |
| `Diff_InMemoryPipelineTotal` | Measures the four Diff stages above together. |
| `Diff_DefaultStatus` | Isolated diagnostic pass over all 627 PersistentStore Rules for SystemDefaults matching. |
| `Diff_ManagedRuleObjectChanges` | Isolated diagnostic pass over the 220 desired / managed Rules for object comparison. |

The two isolated diagnostics run once per sample after the full Diff pipeline. They are not included in `Diff_InMemoryPipelineTotal`. Classification and formatting are timed within the same pipeline sample, not as repeated full passes.

## Establish a baseline

First run `Measure` and review the stage timings. When the workload and environment are suitable, explicitly initialize a baseline:

```powershell
.\performance-tests\Measure-PSNetRulesPerformance.ps1 `
    -Mode InitializeBaseline `
    -BaselinePath '.\performance-tests\PerformanceBaseline.json'
```

Baseline initialization performs a fresh measurement and writes its medians to the explicitly named file. It fails if the file already exists or its parent directory does not exist. Baseline creation is deliberate; `Measure` does not update a baseline automatically.

## Test for regressions

```powershell
.\performance-tests\Measure-PSNetRulesPerformance.ps1 `
    -Mode Test `
    -BaselinePath '.\performance-tests\PerformanceBaseline.json'
```

The test compares the median of every measured metric with the baseline. A metric that is **5% or more slower** fails by default, including a regression of exactly 5%. The limit is a parameter (`-RegressionLimitPercent`); set it from the noise you actually observe — if repeated `Measure` runs on an unchanged tree spread a metric's median by more than the limit, the gate measures noise, not regressions, and the limit (or the iteration count) needs to go up. The baseline must match the current PowerShell / OS / process environment, workload shape and classification distribution, iteration count, and warm-up count.

Use the same machine and PowerShell host for baseline and candidate runs. Review and retain the baseline as a controlled input; do not regenerate it merely to make a regression pass.

## Workload counters (diagnosis)

Timings say *that* a stage is slow; they are too noisy to say *why*. For diagnosis, `-WorkloadCounters` instruments the in-memory copy of the module source (the file on disk is never modified) with a call counter at the top of each function in the harness's target list — the comparison and classification hot paths — and reports how many times each was called during the Capture and Diff scenarios.

```powershell
.\performance-tests\Measure-PSNetRulesPerformance.ps1 -WorkloadCounters -Iterations 1 -WarmupIterations 0
```

Counts are deterministic: the same workload always produces the same counts, so a change that reduces the work shows up as a lower count even when the timing difference is inside the noise. Counts accumulate over every execution of a scenario in the run (warm-ups plus measured iterations), which is why the example above uses one iteration and no warm-up for exact per-pass counts. The counters are included in the report JSON when `-OutputPath` is supplied. Instrumentation fails loudly if a target function is renamed or removed, so the list cannot silently go stale.

## Optional report output

To save the results of a `Measure` run, provide an explicit path:

```powershell
.\performance-tests\Measure-PSNetRulesPerformance.ps1 `
    -OutputPath '.\performance-tests\performance-report.json'
```

The target file must not already exist and its parent directory must already exist. Without `-OutputPath`, the harness prints the report and creates no output file.
