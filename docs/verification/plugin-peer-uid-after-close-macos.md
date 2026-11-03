# macOS で connect 直後に close された接続の peer UID 取得の観測手順と結果記録（PLUG-12・SEC-4・#2252 P2-2）

plugin 境界の UDS 受付（`crates/plugin/src/transport.rs` の `UdsListener::accept`）は、peer UID を取得できないと即エラーにする（fail-closed）。macOS で client が connect 直後に close した接続に対し `getpeereid` が `ENOTCONN` 等で失敗し、正常な client が起動失敗しうるかを実機で確かめる手順と、結果レポートの雛形。実機での実行と判断は人間担当の [#2405](https://github.com/Fandhe-AI/fandhe-container/issues/2405) で、Agent は実行しない。観測用の試験は `crates/plugin/tests/peer_auth.rs` の `plug12_macos_peer_uid_after_client_close_probe`（macOS のみ・`#[ignore]`）で、現状の挙動（取得失敗は即エラー）は変えない。

## 前提

- macOS 実機。非 root の実行ユーザーで足りる。`sudo` は不要で、特別な準備もない
- Rust ツールチェーンは `rust-toolchain.toml` に従う
- 実機のホスト名・アドレス・ユーザー名・資格情報は記録しない（probe の出力は UID 値を含まない）

## 実行

```bash
cargo test -p fandhe-container-plugin --test peer_auth -- --ignored plug12_macos_peer_uid_after_client_close_probe --no-capture
sw_vers
uname -m
git rev-parse HEAD
```

再現性を見るため 3〜5 回繰り返し、結果が揺れるかも記録する（任意）。

## 結果の読み方

出力は JSON 2 行。両方を記録する。

1 行目（`UdsListener::accept` の結果と監査）:

| キー | 意味 |
| ---- | ---- |
| `probe` | 固定値 `peer_uid_after_close` |
| `outcome` | `ok`（受理）または `error` |
| `code` | `error` のとき `PluginErrorCode` の Debug 表記（`ok` のときは空） |
| `audit_count` | 監査行の件数。受理なら 0 |
| `audit_reasons` | 各監査行の理由。`peer_uid_unavailable` か `other` |

`outcome=error` で `audit_count=0` の場合は、peer UID 取得以外（入出力期限の設定等）の失敗でありうる。

2 行目（`getpeereid` の失敗 errno。別の接続で観測。UID は含まない）:

- `{"probe":"peer_uid_errno_after_close","outcome":"ok"}`: 取得できた
- `{"probe":"peer_uid_errno_after_close","outcome":"error","errno":<整数>}`: 取得に失敗。errno は整数でしか出ないため、同じホストで記号名に引き直して記録する（例: `python3 -c 'import errno; print(errno.errorcode[<n>])'`）

## 判断の分岐（記録者は判断せず、オーナーが決める）

- 1 行目 `outcome=ok` かつ 2 行目 `ok`: 現状維持で #2252 の P2-2 を閉じる候補
- 1 行目が `error` で `audit_reasons` に `peer_uid_unavailable`、2 行目の errno が `ENOTCONN` 等: 少数回の許容を設けるか現状維持かをオーナーが決める。許容を入れる場合のコード変更は別 issue で行い、上限・監査・タイムアウト（REPAIR-5）を伴う設計とする
- 上記以外（`Timeout`・監査 0 件の `error` 等）: 結果をそのまま記録し、オーナーへ判断を仰ぐ

## 結果レポートの雛形

記入先は #2405 のコメント（この表を写す）。

| 項目 | 記入 |
| ---- | ---- |
| 実施日 | (記入) |
| 実施者 | (記入) |
| macOS の版（`sw_vers` の ProductVersion・BuildVersion） | (記入) |
| アーキテクチャ（`uname -m`） | (記入) |
| 試験対象の commit（`git rev-parse HEAD`） | (記入) |
| 1 行目の JSON | (記入) |
| 2 行目の JSON | (記入) |
| errno の記号名 | (記入) |
| 繰り返し回数と揺れの有無 | (記入) |
| 備考 | (記入) |
| オーナーの判断 | (記入) |
