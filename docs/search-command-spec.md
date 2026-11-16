# search コマンド仕様

Firewall ルールを条件で検索する `search` コマンドの仕様。Program が存在しない古いルールの抽出も、本コマンドのオプションとして行う。本仕様はレビュー済みであり、細部の既定値は本文の記述どおりとする。

## 1. 目的と範囲

- スナップショット／desired-state の Firewall ルールを、フィールド条件と横断テキストで検索する。
- Program が指定されているのに実ファイルが存在しないルール（古いルール）を抽出できる。抽出のみで終え、削除や unmanage への接続はしない。
- 対象は Firewall ルールのみ。NRPT ルールは対象外。

## 2. CLI

```powershell
.\PSNetRules.ps1 search [-Path <desired-state.json>] [-Source Snapshot|Desired] [条件パラメータ] [-MissingProgram]
```

- `Command` の ValidateSet に `search` を追加する。読み取り専用コマンドであり、`-WhatIf` は受け付けない（既存の検証でエラーになる）。
- search 専用パラメータ（`-Source`、条件パラメータ、`-MissingProgram`）を他のコマンドで指定した場合は、既存の流儀（`-Status` 等）に従ってエラーにする。逆に、他コマンド専用のパラメータ（`-Status`、`-New`、`-Update`、`-Rename`、`-Force`、`-OutputPath`）を search で指定した場合もエラーにする。
- 既存の `-Name` は adopt／unmanage 専用（完全一致）として温存し、search では受け付けない。ルール名で探す場合は `-NamePattern`（部分一致）または `-Text` を使う。

## 3. データソース

- `-Source` で `Snapshot`／`Desired` のいずれかを指定できる。デフォルトは `Snapshot`。
  - `Snapshot`: `-Path` のサイドカーに capture が保存したスナップショットの `comparison.persistentStore` エントリ。
  - `Desired`: `-Path` の desired-state JSON の `firewallRules`。
- 重複排除: 検索は単一ソースに対して行うため、結果は1ルールにつき最大1行とする。`-Text` や `-Sid` で複数のフィールドに一致しても行は重複させない。ソースデータ内に同一 Name が複数ある場合も、最初の1件だけを結果に含める。
- スナップショットが存在しない場合はエラーとし、capture の実行を促す（終了コード1）。
- `Desired` 指定時に desired-state ファイル自体が無い場合はエラー、`firewallRules` が空の場合は0件として扱う。

## 4. 検索対象フィールド

- 両ソースを共通の「正規化ビュー」に寄せてから検索する。フィールド集合はモジュール既存の定義（ルール本体フィールド＋7種のフィルタフィールド）から構成し、search 独自のフィールド定義は持たない。
- SID 検索の対象は Security Filter の `LocalUser`／`RemoteUser`／`RemoteMachine`（いずれも SDDL 文字列）。

## 5. 条件パラメータとマッチング規則

- 条件間は AND、同一パラメータに複数値を指定した場合は OR とする。
- 部分一致は大文字小文字を区別しない。配列フィールドは要素のいずれかが一致すればよい。

| パラメータ | 対象 | 一致方法 |
|---|---|---|
| `-Text <string>` | 全フィールドの文字列表現 | 部分一致。複合値は JSON 化した文字列に対して判定する |
| `-Direction <Inbound\|Outbound[]>` | Direction | 完全一致 |
| `-Action <Allow\|Block[]>` | Action | 完全一致 |
| `-Enabled` / `-Disabled` | Enabled | スイッチ。どちらも無指定なら両方、両方指定はエラー |
| `-Profile <string[]>` | Profile | 部分一致（`Domain, Private` のような複合表記にも当てるため） |
| `-NamePattern <string>` | Name／DisplayName | 部分一致（`-Name` との混同を避けるため別名にする） |
| `-Program <string>` | Program | 部分一致 |
| `-Service <string>` | Service | 部分一致 |
| `-Protocol <string>` | Protocol | 部分一致（`TCP`、数値表記のどちらでも） |
| `-LocalPort <string[]>` / `-RemotePort <string[]>` | 各ポート一覧 | 要素の完全一致。範囲表記（`8080-8090`）はその文字列自体の完全一致として扱い、範囲内の数値での検索はしない |
| `-LocalAddress <string>` / `-RemoteAddress <string>` | 各アドレス一覧 | 部分一致 |
| `-Sid <string>` | LocalUser／RemoteUser／RemoteMachine の SDDL | SID 文字列の部分一致。3フィールドのいずれかに一致すればよい。アカウント名での検索はしない |

- 条件を1つも指定しない場合は全件を表示する。

使用例:

```powershell
# Inbound の Allow のみ
.\PSNetRules.ps1 search -Direction Inbound -Action Allow

# 特定の SID を含むルール
.\PSNetRules.ps1 search -Sid S-1-5-18

# 全フィールド横断の部分一致
.\PSNetRules.ps1 search -Text sql

# desired 側で Program が存在しないルール
.\PSNetRules.ps1 search -Source Desired -MissingProgram
```

## 6. -MissingProgram（古いルールの抽出）

- Program が空でないルールを対象とし、Program の文字列をそのまま `Test-Path` で確認する。環境変数の展開はしない。Program が空欄のルールは確認自体を行わない。
- Package のみのルールは対象外（Package の実在確認はしない）。
- 次に該当するものは「存在しない（Missing）」と断定せず、「確認不能（Unverifiable）」として分けて表示する。
  - ルート付きフルパスでないもの（相対パス、ファイル名のみ）
  - `%` を含むパス（展開しない以上、実在しても「存在しない」になるため）
  - `Test-Path` がアクセス拒否などで例外になったもの
- 他の条件パラメータと併用できる（AND）。
- 出力には Program の値と判定（Missing／Unverifiable）を併記する。判定は「スナップショット／desired に記録された Program 値 × 実行時点のファイルシステム」の合成であり、スナップショットが古ければ Program 値自体も古い可能性があることをヘルプに明記する。

## 7. 出力と終了コード

- 出力は diff と同じ整形に揃える。1ルール1行、基本列は Name、Direction、Action、Enabled、Profile、Program。末尾に一致件数を表示する。
- 0件でも正常終了（終了コード0）とし、0件である旨を表示する。エラー時は終了コード1（既存規約）。
- JSON 出力は v1 では行わない。

## 8. 実装メモ（参考）

モジュール側の想定構成。いずれも既存の命名・構成に倣う。

- `Get-NRSearchableFirewallRule`: スナップショット／desired から正規化ビューのルール一覧を作る。
- `Test-NRFirewallRuleSearchMatch`: 1ルールが条件集合に一致するか判定する（純粋関数として単体テスト可能にする）。
- `Test-NRProgramPathMissing`: Program 値から Missing／Unverifiable／Exists を返す。
- `Invoke-NRSearch`: CLI 入口。読み込み、検索、整形、件数表示。
- 単体テストは既存のテスト構成（フィクスチャ再利用）で、条件マッチングと Program 判定を中心に置く。CLI のパラメータ検証は既存の子プロセステストの流儀で確認する。
