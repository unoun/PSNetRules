# adopt の NRPT 対応仕様

`adopt` コマンドを NRPT ルールにも対応させる仕様。手動で `Add-DnsClientNrptRule` したルールなど、ツール外で作成された NRPT ルールを desired-state に取り込めるようにする。本仕様はレビュー済みであり、細部の既定値は本文の記述どおりとする。

## 1. 目的と範囲

- capture 済みスナップショットに存在する NRPT ルールを、選択して desired-state に取り込める。
- 取り込み済み NRPT ルールの desired 表現を、最新 capture で上書きできる。
- 対象は NRPT ルールのみ。Firewall ルールの adopt は従来どおりで変更しない。プロファイルと Dynamic Keyword Address は対象外。

## 2. 論理 Name の廃止（adopt の範囲）

- NRPT ルールは `Add-DnsClientNrptRule` で直接登録される運用が前提であり、識別は Windows が採番した GUID 名、人の目には DisplayName / Comment がある。desired 側にのみ存在する論理 Name（id）を別途付ける必要はない。
- したがって adopt は論理 id を割り当てない。取り込まれるレコードの `id` は capture が付けた id（＝未対応表ルールでは Windows の GUID 名）のままとする。
- state ファイルの対応表（`nrptRules`）は adopt では読みも書きもしない。未対応表ルールは capture のフォールバック（id := Windows 名）で常に同じ id になるため、対応表なしで一貫する。ツール自身が作成したルール（対応表あり）の再取り込みでも、capture 時点の id で取り込むため対応表は不要である。
- ツールが desired から新規作成するルールの論理 id と対応表の仕組み自体は、本仕様の範囲外であり変更しない。

## 3. CLI

```powershell
.\PSNetRules.ps1 adopt -Nrpt -Name <id> [-Name <id> ...]
.\PSNetRules.ps1 adopt -Nrpt -Update -Name <id> [...]
```

- `-Nrpt` スイッチを adopt 専用として追加する。他のコマンドで指定した場合はエラーにする。
- `-Nrpt` 時は `-Name` が必須であり、値はスナップショット内の NRPT ルールの `id`（通常は `{GUID}` 形式）を指す。
- `-Nrpt` と `-New` / `-Rename` の併用はエラーにする。一括取り込みは行わない（NRPT には Firewall の SystemDefaults 一致のような除外基準がなく、他ソフトが維持するルールまで管理下に入るため、常に名前指定で意図的に選ぶ）。
- `-WhatIf` / `-Confirm` は Firewall の adopt と同様に機能する（Invoke-NRAdopt の SupportsShouldProcess を踏襲）。

## 4. 選択と検証

- 指定した id がスナップショットの `configuration.nrptRules` に存在しない場合はエラー。
- 取り込み（-Update なし）: 指定した id が既に desired にある場合はエラーとし、`-Update` の使用を促す。
- 更新（-Update あり）: 指定した id が desired に無い場合はエラーとし、取り込みの使用を促す。
- 同一 id の重複指定は1回として扱う。
- 書き込み前に、更新後の desired 全体を既存の検証（Assert-NRConfiguration）で検証する。

## 5. 書き込みとプレビュー

- desired ファイルの `nrptRules` に、スナップショットのレコードをそのまま追加（更新時は置換）する。並びは `id` のソート順に整える。
- 書き込み前に desired ファイルのバックアップを作成する（既存 adopt と同じ `pre-adopt` サフィックス）。state ファイルは変更しないためバックアップ対象に含めない。
- プレビューには、id に加えて DisplayName / Namespace / NameServers を表示し、GUID だけでも対象を判別できるようにする。
- 完了時は `Adopted N NRPT rules.` / `Updated N NRPT rules.` を出力する。

## 6. テスト

- adopt はスナップショットと desired のファイルだけを読み書きし、Windows の状態を変更しないため、単体テストで全経路を検証する（契約・統合テストの追加対象はない）。
- 検証項目: GUID id での取り込み、複数 id の一括指定、-Update による置換、既管理 id の取り込みエラー、未管理 id の -Update エラー、未知 id のエラー、-Nrpt と -New の併用エラー、-Name なしのエラー、-WhatIf でファイルが変わらないこと、state ファイルが変更されないこと。
