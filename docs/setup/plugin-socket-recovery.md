# plugin socket の `ALREADY_EXISTS` の見分け方と手動削除

plugin との UDS の bind が `ALREADY_EXISTS` で失敗したときの原因の見分け方と、記録の無い socket を手で消す手順。PLUG-12・PLUG-7・TASK-123 追補・#1859。残余の受容は #1321（オーナー判断 2026-10-12）による。

## 文言と対処

エラーのコードはどれも `ALREADY_EXISTS`。文言はパス・UID を含まない固定の英語文字列で、次のとおり原因を示す。

| 文言 | 原因 | 消してよいか | 対処 |
| ---- | ---- | ------------ | ---- |
| `socket path is in use: its lock is held by another process` | 生存中の listener、fork した子、進行中の bind / 掃除がロックを保持 | 消さない | そのままにする。止めたいなら plugin を終了する |
| `socket path is being changed by another process; retry later` | 他プロセスの bind / 掃除との一時的な競合 | 消さない | 時間をおいて再試行する |
| `socket path has a socket without a matching lock record; confirm no listener is running and remove it manually` | ロックに記録の無い（または一致しない）socket | 確認のうえ消す | 下記の手順に従う |
| `socket path is occupied by an entry that is not a socket; inspect it and remove it manually` | socket でないエントリが占有 | 中身を確かめ、不要なら消す | `ls -l` で種別と中身を確認する |
| `socket path is already in use` | 実 bind の `EADDRINUSE`（bind 直前に別経路が同じ名前を作った競合） | 消さない | 再試行する。続くなら上の表のどれかを疑う |

symlink や他ユーザー所有のエントリは `PERMISSION_DENIED` の別経路で、この手順の対象外。

## 場所

- `$XDG_RUNTIME_DIR/fandhe-container/`
- `XDG_RUNTIME_DIR` が未設定のとき: Linux の root は `/run/fandhe-container/`、Linux の非 root は `/run/user/<euid>/fandhe-container/`、macOS は `$TMPDIR/fandhe-container/`（TASK-123.4・#289）

socket と同名の `<socket 名>.lock` が同じディレクトリに並ぶ。エラー文言にパスは出さないため、どの socket かは起動した plugin の設定（固定名）から判断する。

## 確認の手順

1. 対象が socket か確かめる（`ls -l` の先頭が `s`）。
2. その socket で listen しているプロセスが居ないことを確かめる。Linux は `ss -xlp`（パスで絞る）または `lsof -U`、macOS は `lsof -U`。
3. `<socket 名>.lock` が残っていれば、開いているプロセスが居ないことを確かめる（`lsof <socket 名>.lock`。Linux は `fuser` も可）。

## 削除の手順

- 確認できた socket だけを `rm` で消す。
- ロックファイルは原則消さない。記録の無い socket の場合、失敗した bind が後始末するため通常は残っていない。中身があるロックファイルや、開いているプロセスが居るものは生存中の listener のものでありうるため消さない。

## 補足

- 都度起動の一意名（`oneshot-<pid>-<連番>.sock`）は次の bind を止めない。記録つきの残骸は初期化時の掃除（#1310）が処理する。影響が残るのは固定名の常駐 socket だけ。
- runtime directory は Linux では通常 tmpfs（`/run/user/<uid>` はログアウトか再起動、`/run` は再起動）で消える。macOS の `TMPDIR` は再起動で消える保証が無い。
- 自動回復（二相化・一時名で bind して rename）は採らない。再検討の条件は、常駐 plugin の運用で頻度が問題になったとき。任意の後続として `doctor`（Phase 12・#63）による読み取りだけの検出がありうる。
