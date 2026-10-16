# bind mount（`config.json` の `mounts[]`）

Linux の fandhe-container は、OCI `config.json` の `mounts[]` に書いた bind mount を、コンテナの起動時（`start`）に適用する（TASK-29 追補・#1915・OCI-4・CORE-2・CORE-5・SEC-1。#1907・#1910 のオーナー決定）。本書は利用者向けの書き方と、Docker / runc と異なる既定をまとめる。受け入れ規則の SSOT はコード（`crates/core/src/oci_runtime/bind_mounts.rs` の module doc）で、本書はそこへの案内である。

## 書き方

```json
{
  "mounts": [
    {
      "destination": "/data",
      "type": "bind",
      "source": "/srv/data",
      "options": ["rbind", "rw"]
    }
  ]
}
```

- `source` はホストの絶対パス。`destination` はコンテナ内の絶対パス
- 種類は `type: "bind"`、または `options` に `bind` / `rbind` を含める
- 検証に失敗した `start` は、子プロセスを作らず、状態を Created のまま構造化エラー（`code`・`message`。ERR-2）で終了する

## 受けるオプション

`bind`・`rbind`・`ro`・`rw`・`nosuid`・`nodev`・`noexec`・`exec`・`private`・`rprivate`。後に書いた指定が勝つ（`ro` と `rw`、`noexec` と `exec`）。`rbind` のときだけ再帰的に bind する。

## 拒否するもの

| 指定 | 理由 |
| ---- | ---- |
| `suid`・`dev` | 必須の制限を外すため（SEC-1） |
| `shared`・`rshared`・`slave`・`rslave`・`unbindable`・`runbindable` | 伝播は常に private（ホストへのマウントの漏れを防ぐ） |
| 上記以外のオプション（`defaults`・`rro`・`idmap` を含む） | 未知の指定は fail-closed |
| `bind` と `rbind` の併記 | 意味が曖昧なため |
| 相対パス・`..`・`.`・空要素・`\`・NUL を含む `source`、`source: "/"` | 絶対パスの正規形のみ受ける |
| bundle の rootfs・bundle ディレクトリと同一、またはその祖先の `source` | コンテナが自身の rootfs を書き換える経路を作らない |
| `/proc`・`/sys`・`/dev` とその配下の `destination` | 暗黙のマウントと固定の保護パスがあるため |
| bind 同士で同一・入れ子の `destination` | 子の宛先がホストのディレクトリになるのを防ぐ |
| `linux.readonlyPaths` / `maskedPaths` と重なる `destination` | 保護パスを覆えないようにする |
| bind 以外の種類（`proc`・`tmpfs` など） | 未対応（`UNIMPLEMENTED`） |

## Docker / runc と異なる既定

- `nosuid` と `nodev` を常に付ける。外せない
- 伝播は常に private
- `source` は絶対パスのみ（bundle 相対は不可）
- `source` に symlink が含まれるときは拒否する（辿らない）。存在しない `source` は作らずに拒否する
- `destination` の経路に symlink があるときは拒否する。`destination` のディレクトリは rootfs の中に作る
- rootless（user namespace を使う）の起動経路だけが対象。rootful では受けない

## 制約と未対応

- `ro` の bind は、root が書き込み可能な構成では Landlock が書き込み制限を保証できないため、起動前に拒否される。解消は #1917
- bind 以外の `mounts[]` の種類は未対応
- 状態ルート（`StateStore::host_state_root`）と同一・祖先・子孫の `source` は start が拒否する（字句比較と `canonicalize` した実体の比較。SEC-1）。状態ルートを示せないストアでは bind つきの start を拒否する。検査と適用の間の差し替え（TOCTOU）は rootfs 以外では照合しない（REPAIR-3）
- restart でも、起動時と同じ bind の集合を適用する

## 拒否の記録

分離違反にあたる拒否（設定の検証・launcher 側の重なり検査・適用の段）は、監査ログに記録する（SEC-4）。記録に載せるのはコンテナ内の `destination` だけで、ホスト側の `source` は載せない。
