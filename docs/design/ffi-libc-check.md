# 自前 FFI 宣言と libc の機械照合（#1838・#1837・#1318）

各 crate の `sys` モジュールは syscall・ioctl・FFI の宣言（定数・`#[repr(C)]` 構造体・`extern "C"` 関数）を自前で持つ。
宣言の誤りは分離・特権の欠陥になり得る（CORE-5・SEC-1）ため、`libc` との機械照合をコンパイル時に行う
（MVM-4・REPAIR-7・REPAIR-12）。本書は #1837 の子 issue（#1838・#1840〜#1849）が従う方式を定める。

## 決定の出所

- #1318（オーナー判断 2026-10-12）: `sys` の本体は `libc` へ切り替えず自前宣言のままにし、`libc` は dev-dependencies のみで照合に使う。`nix` は使わない
- 承認済みの版: `libc` `=0.2.189`（#86・#1318）。crates.io には 0.2.190（2026-10-02 公開）があるが、決定どおり `=0.2.189` に固定する

## 依存の扱い

- ルート `Cargo.toml` の `[workspace.dependencies]` に `libc = { version = "=0.2.189", default-features = false }` を置く。照合に使うのは定数・型・関数宣言だけで `std` feature は要らない
- 各 crate は `[target.'cfg(unix)'.dev-dependencies]` から `libc.workspace = true` で参照する（Linux 限定の `sys` は `cfg(target_os = "linux")` でもよい）。`[dependencies]`・`[build-dependencies]` には入れない。`cargo tree -e normal,build -p <crate>` に `libc` が直接依存として現れないことで確かめる
- `Cargo.lock` に `libc` は既にあり、`[[package]]` は増えない（crate の `dependencies` に 1 行増えるだけ）

## 置き場所

`sys`（`src/sys.rs` または `src/sys/` 配下）の中の `#[cfg(test)]` のモジュールに置く（宣言が非公開のため）。
対象の宣言と同じ cfg（`target_os`・`target_arch`・`target_env`）の下に置き、ターゲットごとに違う値はその cfg の下で対応する `libc` の値と照合する。期待値に他ターゲットの値やリテラルを使わない。
crates/cli では `imp` の子 `libc_abi`（`imp` の非公開宣言用）と、`tests` の子 `libc_abi_fixtures`（試験側の非公開定数用）。

## 照合の 3 種と標準形

照合はすべて `const _: () = assert!(…);` または型付きの `const _` で、コンパイル時に評価される。関数は呼ばず、新しい `unsafe` は足さない。

1. 定数: `const _: () = assert!(自前 == libc::X);`。型が違うときに `as` で合わせて切り詰めを隠さない
2. `#[repr(C)]` 構造体: `size_of`・`align_of` の一致に加え、フィールドのオフセットまで照合する（`flags` と `restorer` の入れ替えのようなサイズの変わらない誤りを検出するため）。`libc` のフィールドが pub なら `offset_of!` で比べ、フィールド型のサイズは型名を明記して比べる（例: `size_of::<[u64; 16]>() == size_of::<libc::sigset_t>()`）。フィールドが非公開（`sigset_t` の中身など）ならサイズ・アラインメントだけを照合し、その旨をコメントに書く。自前と `libc` でフィールド型が違う場合（`usize` と `Option<extern "C" fn()>` など）はサイズ・オフセットで照合し、理由を書く
3. `extern "C"` 関数: 期待する型を `libc` のスカラー型の別名（`c_int`・`pid_t`・`size_t`）で書いた関数ポインタ型の `const _` に、自前の宣言と `libc` の関数をそれぞれ代入する
   - 例: `const _: unsafe extern "C" fn(libc::pid_t, libc::c_int) -> libc::c_int = kill;` と同じ型への `libc::kill`
   - 自前の構造体へのポインタを含む場合は、自前側を `*const layout::SigAction`、`libc` 側を `*const libc::sigaction` で別々に書く（構造体の同一性は 2. が保証する）
   - `-> !`（`_exit`）はそのまま関数ポインタ型に書く
   - 可変長引数: 自前の宣言は `libc` が可変長のときに限り可変長にし、同じ可変長の関数ポインタ型へ代入する。`libc` が可変長で自前が固定引数なら aarch64-apple-darwin で ABI が不一致になるため、注記で済ませず食い違いとして報告する
   - `link_name` の違い（macOS の `$UNIX2003`、glibc の `__xpg_*` など）は型を照合し、シンボル名の違いをコメントに書く
   - 型付きのハンドラ型が `libc` に無い（`sighandler_t` は `size_t`）コールバックは、引数の型だけを `extern "C" fn(libc::c_int)` への代入で照合し、理由を書く

## 対象外の書き方

`libc` に対応物が無いもの（カーネル ABI の構造体、raw syscall 専用の定数など）、名前が違うもの、FFI でないもの、照合に関数の呼び出しが要るものは、黙って省かず、理由と一次情報（ヘッダ名・バージョン）を照合モジュールのコメントに書く。
crates/cli の対象外: `REAP_LIMIT`（`Duration`。FFI ではない）、`mask_of` のビット規則（照合に `sigaddset` の呼び出しが要る。読み戻し試験が 0x4003 で検証している）。
試験関数内のローカル定数（`SIGPROF`・26）は項目として参照できないため、`libc` 側の値を assert して該当する試験名をコメントに書く。

## 食い違いが見つかったとき

照合の側を宣言に合わせて通さない。実装を止めて報告し、宣言の修正は別 issue で行う。

## CI のどこで評価されるか（#1837 の受け入れ条件）

| ターゲット | 評価するジョブ | 内容 |
| ---------- | -------------- | ---- |
| x86_64-unknown-linux-gnu | `rust-ci`（clippy・test の `--all-features`）・`platform-ci`（ubuntu の `make lint`・`make test`） | コンパイル時検査（試験の実行を含む） |
| aarch64-unknown-linux-gnu | `cross-target-check`（`cargo check`・`cargo clippy` の `--all-targets --all-features`） | 型検査（const の評価は行われる。試験は実行しない） |
| aarch64-apple-darwin | `cross-target-check`（既定 feature の clippy を含む）・main の `platform-ci`（macos。ネイティブ） | PR では型検査、main ではネイティブ |
| x86_64-apple-darwin | なし | CI の空白。手元で `cargo check --all-targets --target x86_64-apple-darwin` を推奨する |
| Windows | 対象外 | `sys` は `cfg(unix)`。Windows API の自前宣言は #1837 の範囲外 |

## 手元での評価の確認（#1838）

値をわざとずらして `cargo check -p fandhe-container-cli --all-targets --target <target>` が失敗することを確かめた（ずらした変更はコミットしていない）。

| ずらした宣言 | aarch64-unknown-linux-gnu | aarch64-apple-darwin |
| ------------ | ------------------------- | -------------------- |
| `SA_RESTART` の値 | exit 101・E0080（`assertion failed`） | exit 101・E0080 |
| `SigAction` のフィールド順（サイズは不変） | exit 101・E0080（`flags` のオフセット） | exit 101・E0080（`mask` のオフセット） |
| `raise` の引数型 `i32` → `i64` | exit 101・E0308 | exit 101・E0308 |

## 適用状況

crates/cli（#1838）・crates/oci（#2590。#1837 の範囲に入れる。2026-10-23 のオーナー判断）・crates/net（#1841）・crates/plugin（#1843）・crates/plugin-windows（#1846）は適用済み。残りの crate は #1840〜#1849（core の #1849 では、#2628 で足した `sendfile` の型〔`off_t *`・`size_t`・`ssize_t`〕の照合も含める。#2759）。`sys` に新しい宣言を足す PR は同じ PR で照合も足す（`.claude/rules/coding-rust.md`）。関連: `.claude/rules/ci.md`「クロス型検査」。

crates/oci の対象外（理由は照合モジュールのコメント）: FFI でない安全なラッパー群、`openat2` に渡す大きさ（`OpenHow` のサイズ照合に含まれる）、`struct linux_dirent64`（カーネルの構造体で `libc` に無い。ヘッダ部のオフセットが一致する `libc::dirent64` で `for_each_dirent` の `NAME_OFFSET` と `d_reclen` の位置を代わりに照合）。oci の `O_*` は `open_how.flags` に合わせて `u64` のため、`libc` の `c_int` を負でないことを確かめて広げて比べる。

crates/plugin-windows（#1846）も適用済み。`sys` の `imp` にある `signal(3)` の宣言・`SIG_ERR`・`SIGTERM`（cfg 3 定義）・ハンドラ `on_sigterm` の引数型を `const` 検査で照合した（4 種すべて。対象外は FFI でない `SIGTERM_RECEIVED` と安全なラッパー群。理由は照合モジュールのコメント）。

crates/net の対象外（理由は照合モジュール `libc_abi` のコメント）: 対応外アーキテクチャの `consts`（カーネルへ渡さないプレースホルダ）・`SUPPORTED`・FFI でない項目、`SockaddrNl::nl_pad` のオフセット（`libc::sockaddr_nl` で非公開のため自前側のオフセットと `nl_family`・`nl_pid` の一致で代替）。`sockaddr` を取る 4 関数は自前が `SockaddrNl` を指すため、ポインタ型を別々に書いて照合する。照合は定数 45 件（`AF_NETLINK` は `u16` に範囲検査して比較）・構造体 2 件・関数 12 件。

crates/plugin（#1843）は `sys.rs` の末尾の `libc_abi`（cfg ごとの子モジュール）と、`tests` の子 `libc_abi_fixtures` で照合する。`MIT OR Apache-2.0` の境界ライブラリだが、dev-dependency のため製品の依存グラフは変わらない。対象外と扱いは次のとおり。

- `waitid` の `idtype`: 自前は `i32`、`libc` は `idtype_t`（`c_uint`）。C の列挙型で列挙子がすべて負でないため `libc` は符号なしを選ぶ。幅・アラインメントは同じで、32 bit 整数引数の渡し方は符号で変わらず ABI は一致する。型の綴りの違いとして、関数は引数の型を別々に書いて照合し、`P_PID` は負でないことを確かめて比べた。自前の宣言を `u32` に揃えるかはオーナー判断（`sys` の本体は変えていない）
- 関数本体・試験関数の中のローカル項目（`O_PATH`・`SOL_LOCAL`・`LOCAL_PEERPID`・`PROC_PIDTASKINFO`・`ProcTaskInfo`・`proc_pidinfo`・`peer_pid` の `getsockopt`・`WNOHANG`・`EPROTO`）は項目として参照できない。上の「試験関数内のローカル定数」の規則を構造体と関数へ広げ、`libc` 側の値・サイズ・オフセットを自前と同じ値で assert し、関数は自前の宣言と同じ並びで書いた型へ `libc` の関数を代入する
- `statx` / `statx_timestamp` は `libc` が gnu でだけ定義するため `target_env = "gnu"` の下で照合する。時刻は自前が配列、`libc` が個別フィールドなので、名前の対応をつけてオフセットで比べる。`pad0` は `libc` 側が非公開
- Linux の `siginfo_t` の `si_pid` は `libc` がアクセサの裏に隠し `offset_of!` で取れない。本体の assert が担う
- macOS の `link_name`（`$INODE64`）は型の照合で検査できない
- FFI でない値（`PROBE_EINTR_RETRIES`・`CREATED_LOCK_WAIT_*`・`UCRED_SIZE`・`MTIME_INDEX` など）は対象外

crates/gpu（#2979・#2980 で `sys` を新設）は未適用。照合は #1837 の子 #2989 で行う。dev-dependencies の `libc`（=0.2.189）だけを使い、追加には oci（#2590）と同様に crate ごとのオーナー承認が要る。

なお rustdoc は dev-dependencies を解決しないため、`#[cfg(test)]` の外のドキュメントコメントから `libc::…` へ intra-doc リンクを張らない（バッククォートのみ。#1300）。
