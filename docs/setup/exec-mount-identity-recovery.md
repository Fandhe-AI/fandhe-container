# exec のマウント識別子が無い旧コンテナの作り直し

`exec` は、launch 時に記録した bind mount などの識別子（`mnt_id`・`dev`・`ino`・`ro`）と、exec 時点のマウントを照合してから Landlock を再適用する（SEC-1・SEC-4・CORE-5・#3201。#2130 の残り）。識別子の記録が入る前に作ったコンテナの `state.json` には識別子が無く、重ねられたマウント（overmount）を検出できないため、`exec` は fail-closed で拒否する。

## 症状

`exec` が次の内容で失敗する（段 `landlock`・コード `FAILED_PRECONDITION`。監査には記録されない。違反の試行ではないため）。

```text
launch isolation record has no mount identities; recreate the container
```

## 見分け方

`state.json` の `launchIsolation.landlock.rules` のうち `origin` が `mount`・`tmpfs`・`implicit` の要素に `mount` オブジェクトが無ければ旧記録である。Mount 由来のルールが無い（rootfs だけの）コンテナは影響を受けない。

## 手順

1. 対象コンテナを停止する（`stop`）。
2. 削除する（`delete`）。named volume の中身は残る。
3. 同じ bundle・オプションで作り直す（`create` → `start`）。新しい記録には識別子が入り、`exec` が通る。

識別子を手で `state.json` へ書き足さない。launch 時に子が観測した値だけが信頼できる。

## 照合で拒否される場合

作り直した後でも `exec` が `landlock_mount_identity_mismatch`（識別子の不一致）または `landlock_mount_not_root`（マウントのルートでない）で拒否されたら、launch 後にそのパスの上へ別のマウントが重ねられている。監査ログの記録を確認し、重ねたマウントの出どころを調べてからコンテナを作り直す。
