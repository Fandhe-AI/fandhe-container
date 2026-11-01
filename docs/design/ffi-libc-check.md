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
| aarch64-unknown-linux-musl（製品のゲストのターゲット。guest-init のみ） | `cross-target-check` の `cargo check` / `cargo clippy -p fandhe-container-guest-init --all-targets` | 型検査（`cfg(test)` の const の評価は行われる。試験は実行しない） |
| x86_64-unknown-linux-musl・aarch64-unknown-linux-musl の core・net | なし（対象外。決定は「musl の扱い（#3103）」） | core・net を musl で使う配布物が無いため評価しない |
| aarch64-apple-darwin | `cross-target-check`（既定 feature の clippy を含む）・main の `platform-ci`（macos。ネイティブ） | PR では型検査、main ではネイティブ |
| x86_64-apple-darwin | なし | CI の空白。手元で `cargo check --all-targets --target x86_64-apple-darwin` を推奨する |
| Windows | 対象外 | `sys` は `cfg(unix)`。Windows API の自前宣言は #1837 の範囲外 |

## musl の扱い（#3103）

決定: crates/core・crates/net の musl（`x86_64-unknown-linux-musl`・`aarch64-unknown-linux-musl`）は libc 照合の対象外とする（MVM-4・REPAIR-7・REPAIR-12・MS-6）。CI で core・net の musl の型検査・照合は行わない（新しいジョブ・check-run も足さない）。

根拠:

- musl の配布ターゲットは crates/guest-init（`aarch64-unknown-linux-musl`）だけで、guest-init は std のみ（`cargo tree -p fandhe-container-guest-init -e normal --target aarch64-unknown-linux-musl` は自身だけ。core・net を引かない）。
- core・net を使う crate（cli・supervisor・cri・oci・plugin-cri・plugin-mcp）はすべて gnu の Linux 向けで、配布物の生成（`release.yml`）は発火条件を無効化中。

musl に関係する分岐の一覧:

- 製品コードに `cfg(target_env = "musl")` の分岐は無い。宣言は glibc の原型に合わせてあり、musl との差（`ioctl` の `request`、`renameat2` が musl 1.2.6 以降など）は各宣言のコメントに書いてある。
- core の照合のうち `cfg(target_env = "gnu")` に限ったもの: `libc_consts_checks!` の gnu 節（`BINDERFS_SUPER_MAGIC`・`NS_GET_*`・`TIOCGPTN`・`TIOCSPTLCK`・`RLIMIT_*`・`PTRACE_CONT`）、`seccomp_notify.rs` の ioctl 定数 3 件、`libc_abi` の `StatFs.f_flags`、`ioctl`・`prlimit`・`renameat2` の関数型、`MsgHdr`・`CmsgHdr`。
- net の製品コードに `target_env` の分岐は無い。照合側では `sys/holder.rs` の `MsgHdr` の照合だけを `cfg(target_env = "gnu")` に限る（core の `seccomp_notify` と同じ扱い。musl の `msghdr` は非公開のパディングと型が glibc と違うため）。他の照合は arch の cfg のみ。

gnu 限定の分岐を残す理由: 外すと musl では型の違い（`c_int`・非公開フィールド）で通らないか、`as` の読み替えで通すことになり照合の意味が無くなる。gnu に限る形は、将来 musl を採るときに musl の節を足す土台にもなる。`compile_error!` 等で musl のビルドを機械的に禁じることはしない（製品挙動の変更になり、本 issue の範囲外）。

手元の確認（commit 315e25aa。`aarch64-unknown-linux-musl` のみ。`x86_64-unknown-linux-musl` は toolchain に入っておらず未確認）:

| 確認 | 結果 |
| ---- | ---- |
| `cargo check -p fandhe-container-net --all-targets --target aarch64-unknown-linux-musl` | 成功 |
| `cargo check -p fandhe-container-core --lib --bins --target aarch64-unknown-linux-musl` | 成功 |
| `cargo check -p fandhe-container-core --all-targets --target aarch64-unknown-linux-musl` | 失敗。`StatFs` の照合の `libc::__fsword_t`（gnu にしか無い）が E0425。名前解決で止まるため、その先の `const` 評価で musl に食い違いがあるかは未確認 |

再検討の条件: musl で core・net をリンクする crate・配布物が加わったとき（`rename_noreplace_at` の doc の条件と同じ）。その場合の作業案（採否・CI の追加はオーナー承認事項で、未実施）:

- `cross-target-check` の既存ジョブにステップとして `cargo check` / `cargo clippy -p fandhe-container-core -p fandhe-container-net --all-targets --all-features --target <musl target>` を足す（新しいジョブ・check-run は増やさない）
- `__fsword_t` の照合を gnu に限り、musl の `--all-targets` を通す
- musl の節を照合に足す（`c_int` の `Ioctl`・`resource`、`renameat2` の musl 1.2.6 前提、`msghdr` の非公開パディング）
- 製品の宣言（`ioctl` の `request` 型など）を musl に合わせて cfg で分けるかを判断する

## 手元での評価の確認（#1838）

値をわざとずらして `cargo check -p fandhe-container-cli --all-targets --target <target>` が失敗することを確かめた（ずらした変更はコミットしていない）。

| ずらした宣言 | aarch64-unknown-linux-gnu | aarch64-apple-darwin |
| ------------ | ------------------------- | -------------------- |
| `SA_RESTART` の値 | exit 101・E0080（`assertion failed`） | exit 101・E0080 |
| `SigAction` のフィールド順（サイズは不変） | exit 101・E0080（`flags` のオフセット） | exit 101・E0080（`mask` のオフセット） |
| `raise` の引数型 `i32` → `i64` | exit 101・E0308 | exit 101・E0308 |

## 適用状況

crates/cli（#1838）・crates/oci（#2590。#1837 の範囲に入れる。2026-10-23 のオーナー判断）・crates/net（#1841）・crates/io（#1842）・crates/plugin（#1843）・crates/cri（`sys.rs` の `libc_abi`。#872）・crates/supervisor（#1840）・crates/plugin-windows（#1846）・crates/platform-macos（#1844）・crates/plugin-macos（#1845）は適用済み。crates/core（syscall 番号〔#1847〕・番号以外の定数〔#1848〕・構造体と関数の型〔#1849〕）も適用済み。#1837 の子 #1840〜#1849 はすべて完了している。未適用は crates/microvm（`sys` の `ioctl` 宣言の型。dev-dependency の `libc` の追加が crate ごとの承認待ち。`KVM_*` の ioctl 番号は `libc` に無くカーネル ABI のため対象外。TASK-74.1.1・#874）・crates/gpu（#2989）と crates/plugin-cri（`sys.rs` の `signal` と SIGTERM / SIGINT の番号。dev-dependency の `libc` の追加が承認待ちのため。#3226）で、dev-dependencies に `libc` を持たない crate（crates/guest-init・crates/platform-windows の手作業の突き合わせなど）には機械照合が無い。`sys` に新しい宣言を足す PR は同じ PR で照合も足す（`.claude/rules/coding-rust.md`）。関連: `.claude/rules/ci.md`「クロス型検査」。

crates/oci の対象外（理由は照合モジュールのコメント）: FFI でない安全なラッパー群、`openat2` に渡す大きさ（`OpenHow` のサイズ照合に含まれる）、`struct linux_dirent64`（カーネルの構造体で `libc` に無い。ヘッダ部のオフセットが一致する `libc::dirent64` で `for_each_dirent` の `NAME_OFFSET` と `d_reclen` の位置を代わりに照合）。oci の `O_*` は `open_how.flags` に合わせて `u64` のため、`libc` の `c_int` を負でないことを確かめて広げて比べる。

crates/io（#1842）: `sys.rs`（`libc_abi`・`beneath::libc_abi`・`tests::libc_abi_fixtures`）と `sys/vsock.rs`（`libc_abi`）・`sys/uds.rs`（`libc_abi`。`SockaddrUn` の OS 別レイアウト・errno・`socket` の型。#3165）で、`Ucred`・`SockaddrVm`・`PollFd` のサイズ・アラインメント・フィールドオフセット、`O_*`・`AT_*`・errno・`SOL_SOCKET` 等の定数、`beneath::raw` ほか全 FFI 関数の型を照合する。`libc` 0.2.189 の `sockaddr_vm` は旧ヘッダ形（`svm_zero: [u8; 4]`）で `svm_flags` を持たないため、自前の `svm_flags`＋`svm_zero[3]` は末尾 4 バイトの位置・サイズで照合する。DIR・`dirent`・`sockaddr` はポインタ先の型が自前と `libc` で別書き（不透明ポインタ・先頭バイト・`SockaddrVm`）のため、関数は別々の型で書き、`dirent` の `d_ino`・`d_name` のオフセットは `offset_of!` で照合する。`connect` の宣言は vsock と UDS で別の引数型にすると `clashing_extern_declarations` が出るため、`sys.rs` の `sock_raw` に `*const c_void` 版を 1 か所だけ置いて両方が使う（照合は `sys/vsock.rs`・`sys/uds.rs` の `libc_abi` で `*const c_void` のまま行う）。`vsock.rs` の `map_errno` の数値リテラルは `libc` の errno と値を照合する。対象外（理由は各モジュールのコメント）: `UCRED_SIZE`・`UCRED_LEN`・`SOCKADDR_VM_LEN`（サイズ照合に含まれる）、`MAX_FULL_FSYNC_EINTR_RETRIES`・`consts::SUPPORTED`（FFI でない）、`LINKAT_FLAGS`（`libc` に無い方針値。`AT_SYMLINK_FOLLOW` を含まないことだけ照合）、対応外 arch 用 `consts`、`windows.rs`。

crates/plugin-macos（#1845）は適用済み。照合は `sys.rs` の `imp::libc_abi`（`SIGTERM` の 3 腕・`SIG_ERR`・`signal` の型・`on_sigterm` の引数型）と `libc_abi`（`NOFOLLOW_NONBLOCK_FLAGS` の 3 腕・`ELOOP` の 2 腕）。対象外は `None` の腕・Windows の `ELOOP` 腕・FFI でない安全なラッパーで、構造体は無い。評価対象外のターゲット（Linux mips / mips64 / sparc64、illumos 等）では `ELOOP` の宣言が `libc` と食い違う可能性があり、別 issue で扱う。

crates/plugin-windows（#1846）も適用済み。`sys` の `imp` にある `signal(3)` の宣言・`SIG_ERR`・`SIGTERM`（cfg 3 定義）・ハンドラ `on_sigterm` の引数型を `const` 検査で照合した（4 種すべて。対象外は FFI でない `SIGTERM_RECEIVED` と安全なラッパー群。理由は照合モジュールのコメント）。

crates/net の対象外（理由は照合モジュール `libc_abi` のコメント）: 対応外アーキテクチャの `consts`（カーネルへ渡さないプレースホルダ）・`SUPPORTED`・FFI でない項目、`SockaddrNl::nl_pad` のオフセット（`libc::sockaddr_nl` で非公開のため自前側のオフセットと `nl_family`・`nl_pid` の一致で代替）。`sockaddr` を取る 4 関数は自前が `SockaddrNl` を指すため、ポインタ型を別々に書いて照合する。照合は `sys.rs` と `sys/` 配下の 4 ファイルの `libc_abi` で行う（数え方: 定数は `consts::X == libc::X` の比較 1 件、構造体は `size_of`・`align_of`・`offset_of!` で照合する `#[repr(C)]` の型 1 件、関数は自前と `libc` の対 1 件。`sa_family_t`・`SUN_PATH_LEN`・`id_t`・`idtype_t` 等の型の幅だけの確認は件数に入れない）。

| ファイル | 定数 | 構造体 | 関数 | 補足 |
| -------- | ---- | ------ | ---- | ---- |
| `sys.rs`（#1841・#3045） | 45（`AF_NETLINK` は `u16` に範囲検査） | 2（`sockaddr_nl`・`pollfd`） | 12 | 上記の対象外のとおり |
| `sys/holder.rs`（#3249） | 20 | 3（`iovec`・`ucred`・`msghdr`。`msghdr` は gnu のみ） | 7 | `CapUserHeader`・`CapUserData` は `libc` に無く対象外。`sendmsg`・`recvmsg` の `msghdr` 引数は型を別々に書く |
| `sys/pasta.rs`（#3319） | 3 | 0 | 1（`kill`） | なし |
| `sys/process.rs`（#3320） | 9 | 0 | 3（`syscall`・`waitid`・`setsid_raw` と `setsid`） | `waitid` の `infop` と idtype の型は別々に書く |
| `sys/unix_socket.rs`（#3517・#3071） | 4（`AF_UNIX` は `u16` に範囲検査） | 1（`sockaddr_un`） | 2（`socket`・`connect`） | `connect` の `sockaddr` 引数は型を別々に書く |
| 合計 | 81 | 6 | 25 | |

crates/net の uapi 定数（`sys.rs` の外にある netlink・rtnetlink・nfnetlink・nf_tables の定数。#3102・NET-1・MVM-4・REPAIR-12）は、宣言の隣の `libc_abi`（`#[cfg(all(test, target_os = "linux"))]`。uapi の値はアーキに依らないため arch の cfg は付けない）で照合する。`cfg(test)` だけにすると macOS・Windows の `cross-target-check` で `libc::` が解決できず落ちるため、Linux 限定にする。対象は `netlink.rs`・`netlink_route/link.rs`・`netlink_route/addr_route.rs`・`nftables_batch.rs`・`nftables_batch/table_chain.rs`・`nftables_batch/ack.rs`・`nftables_rules/{rule,nat,masq,payload,cmp,data,meta}.rs`（`nftables_rules/bitwise.rs` の `NFTA_BITWISE_*`・`NFT_BITWISE_*` は libc 0.2.189 に対応物が無く照合なし。#3060）・`network/publish.rs`。マクロ `libc_const_eq!` は `lib.rs` の `pub mod` 列より前に置く（core の同名マクロの複製。`macro_rules` はテキスト順にしか見えないため）。

- 照合: `libc_const_eq!` の呼び出し 129 件（`const fn`・newtype 経由の評価 25 件を含む。`NftFamily::nfproto`・`NfInetHook::value`・`NftCmpOp::wire_value`・`NatType` / `NatFamily` の `wire_value`・`NftRegister`）。構造体のサイズ 6 件（`nlmsghdr`・`nlattr`〔`rtattr` も同値〕・`ifinfomsg`・`ifaddrmsg`。`BATCH_MARKER_LEN` は `nlmsghdr` + `NFGENMSG_LEN`）。`NftCmpOp::from_wire` は `libc` の値から復元する `#[test]` を 1 件足した
- 名前が違う対応: `ALIGN_TO` ↔ `NLA_ALIGNTO`（`libc` に `NLMSG_ALIGNTO` が無い）、`NFT_NAME_MAXLEN` ↔ `NFT_TABLE_MAXNAMELEN` と `NFT_CHAIN_MAXNAMELEN`、`NFT_REG_AREA_BYTES` ↔ `(NFT_REG32_15 - NFT_REG32_00 + 1) * NFT_REG32_SIZE`（派生値）
- `NLA_TYPE_MASK`: C のヘッダーが int の補数で定義するため `libc` の値は負数（-49153）になる。`nla_type` は `__u16` なので 16 bit 幅に丸めて比べる（宣言は直さない）
- `libc` に無いもの（出典を定義の横に書いた。書式は「出典: `include/uapi/<ヘッダー>`。Linux 7.0.14 の uapi〔linux-libc-dev 7.0.0-38.38〕で値を確認。libc 0.2.189 に無い」）: `NLMSGERR_ATTR_*`・`VETH_INFO_PEER`・`IFALIAS_MAX_LEN`（`IFALIASZ` = 256）・`RTMSG_LEN`・`NFGENMSG_LEN`・`NFTA_*` 全般・`NAT_RANGE_*` / `NF_NAT_RANGE_*`（nat と masq の重複定義は crate 内の一致で固定）・`is_dump_request` 内のローカル定数 `RTM_BASE`（その場のコメント）。出典の値は C の小さなプログラムで uapi ヘッダーから実際に出力して突き合わせた
- 対象外（理由は各 `libc_abi` のコメント）: 方針値・上限（`MAX_*`・受信バッファ長・`MAX_ATTR_PAYLOAD_LEN`）、uapi に名前が無い値（`NFT_RULE_MAXEXPRS` はカーネル内部の上限、`NFT_PAYLOAD_MAX_FIELD` はカーネルの検査から導いた値、`NFT_EXPR_NAME_MAXLEN`）、expr 名の文字列、DNS ヘルパー・記録形式の定数、`dns_helper::is_msgsize` の `EMSGSIZE`（`sys.rs` の `consts::EMSGSIZE` が照合済み）
- 確認: 値をわざとずらして `const` 評価が `E0080` で止まることを 4 例で確かめて戻した（素の `u16` の `IFLA_IFALIAS`、`u8` を広げて比べる `NFT_MSG_NEWRULE`、丸めて比べる `NLA_TYPE_MASK`、`const fn` 経由の `NfInetHook::Forward.value()`）
- 新しい `unsafe`・関数呼び出し・依存の変更は無い。`sys.rs` の外に uapi 定数を足す PR は、同じ PR で照合か出典を足す

crates/plugin（#1843）は `sys.rs` の末尾の `libc_abi`（cfg ごとの子モジュール）と、`tests` の子 `libc_abi_fixtures` で照合する。`MIT OR Apache-2.0` の境界ライブラリだが、dev-dependency のため製品の依存グラフは変わらない。対象外と扱いは次のとおり。

- `waitid` の `idtype`: 自前は `i32`、`libc` は `idtype_t`（`c_uint`）。C の列挙型で列挙子がすべて負でないため `libc` は符号なしを選ぶ。幅・アラインメントは同じで、32 bit 整数引数の渡し方は符号で変わらず ABI は一致する。型の綴りの違いとして、関数は引数の型を別々に書いて照合し、`P_PID` は負でないことを確かめて比べた。自前の宣言を `u32` に揃えるかはオーナー判断（`sys` の本体は変えていない）
- 関数本体・試験関数の中のローカル項目（`O_PATH`・`SOL_LOCAL`・`LOCAL_PEERPID`・`PROC_PIDTASKINFO`・`ProcTaskInfo`・`proc_pidinfo`・`peer_pid` の `getsockopt`・`WNOHANG`・`EPROTO`）は項目として参照できない。上の「試験関数内のローカル定数」の規則を構造体と関数へ広げ、`libc` 側の値・サイズ・オフセットを自前と同じ値で assert し、関数は自前の宣言と同じ並びで書いた型へ `libc` の関数を代入する
- `statx` / `statx_timestamp` は `libc` が gnu でだけ定義するため `target_env = "gnu"` の下で照合する。時刻は自前が配列、`libc` が個別フィールドなので、名前の対応をつけてオフセットで比べる。`pad0` は `libc` 側が非公開
- Linux の `siginfo_t` の `si_pid` は `libc` がアクセサの裏に隠し `offset_of!` で取れない。本体の assert が担う
- macOS の `link_name`（`$INODE64`）は型の照合で検査できない
- FFI でない値（`PROBE_EINTR_RETRIES`・`CREATED_LOCK_WAIT_*`・`UCRED_SIZE`・`MTIME_INDEX` など）は対象外

crates/core の syscall 番号（#1847）の対象外（理由は照合モジュール `libc_abi` のコメント）: 対応外アーキテクチャの `consts` と `seccomp_notify` の対応外側（`ArchSysNo::UNSUPPORTED` で番号を持たない）、x32・ILP32（`target_pointer_width = "64"` の cfg で対応外）。照合は x86_64 と aarch64 の `consts` の 27 件ずつと `SYS_SECCOMP`（`sys/seccomp_notify.rs`）の各 1 件で、値は既存の `ArchSysNo::get` と試験専用の `SyscallNumber::raw` を通す `const fn` で読み、`sysno` の型の保証は変えない。

crates/core の番号以外の定数（#1848）: 照合は `const` 評価で、試験専用の `libc_const_eq!`（両辺の型を引数で明記し `as i128` で比べる。64 bit 以下の整数では値を切り詰めず、`libc` の型が変われば E0308 で表に出る）を使う。x86_64 と aarch64 の `consts` は名前が同じ 183 件ずつ（`SYS_*`・`SUPPORTED` を除く）で、一覧 `libc_consts_checks!` を各 arch の `consts::libc_abi` から展開して 164 件ずつ照合し、19 件は `libc` に対応物が無く対象外（fs magic 6 件・`ST_VALID`・bpf 6 件・`KCMP_VM`・`KEXEC_SEGMENT_MAX`・Landlock 3 件・`LINUX_CAPABILITY_VERSION_3`。一次情報は `libc_consts_checks!` のコメント）。164 件のうち 24 件（`Ioctl` 型の `NS_GET_*`・`TIOCGPTN`・`TIOCSPTLCK`、`RLIMIT_*`、`PTRACE_CONT`、`BINDERFS_SUPER_MAGIC`）は `libc` の型が環境で変わる、または gnu にしか無いため `target_env = "gnu"` に限る（musl は `c_int` で `TIOCGPTN` が負になり、読み替えで通さない。core は musl 向けに CI でビルドしない。「musl の扱い（#3103）」参照）。名前が違う対応は `OPEN_TREE_AT_*`・`MOUNT_SETATTR_AT_*`（`libc` は `AT_EMPTY_PATH`・`AT_RECURSIVE`）、`PROC_MAGIC`（`PROC_SUPER_MAGIC`）、`DEVPTS_MAGIC`（`DEVPTS_SUPER_MAGIC`）、`ENOENT_ERRNO`・`EPERM_ERRNO`。`consts` の外は `sys.rs` 最上位の `libc_abi` で 9 件（`AT_FDCWD`・`TMPFS_MAGIC`・`PROC_MAGIC`・`DEVPTS_MAGIC`・`SIG_DFL`・`SIG_ERR`・`SIG_IGN`・`PIDFD_SIGNAL_PROCESS_GROUP`・`renameat2` 内の `RENAME_NOREPLACE`）、`sys/seccomp_notify.rs` で 18 件（ioctl の 3 件は gnu のみ）、`sys/macos.rs` で最上位 4 件と `plugin_fs` 20 件〔#3096 で `AT_SYMLINK_NOFOLLOW`・`S_IFMT`・`S_IFREG`・`S_IFDIR`・`S_IFLNK` の 5 件を追加〕を照合する（`sys/bpf.rs` に照合できる定数は無い。内部の上限と方針値のみ）。対象外の方針値・試験の固定値は `sys.rs` 最上位の `libc_abi` のコメントに列挙した。macOS の `ACL_TYPE_EXTENDED`・`ACL_FIRST_ENTRY` は `libc` の apple に定義が無く未照合のまま残る（Apple SDK の `sys/acl.h` との照合は #2369 から未了）。`libc` の dev-dependency は macOS の照合のため `cfg(target_os = "linux")` から `cfg(unix)` に広げた（版・`Cargo.lock` は不変）。値をわざとずらして評価が失敗することを、そのまま比べる `O_NOFOLLOW`（aarch64）、広げて比べる `MOUNT_ATTR_NODEV`、gnu の ioctl `TIOCGPTN`、名前が違う `MOUNT_SETATTR_AT_RECURSIVE`、`consts` の外の `PROC_MAGIC`、`seccomp_notify` の `SO_PASSCRED`、macOS の `plugin_fs::F_GETPATH` で確認した（いずれも E0080）。

crates/core の `mount`・`syscall`・`ioctl`・`prctl`・`sendfile`・`poll` の extern 宣言は LP64 の x86_64・aarch64 だけで宣言し、それ以外は `unsupported_ffi`（`-1` / `ENOSYS` 相当を返すスタブ）に倒す（#3202・MVM-4・SUP-6）。照合の cfg は宣言の cfg と一致させる。

crates/core の構造体と関数の型（#1849）: 照合は `sys.rs` 最上位の `libc_abi`（構造体 6 種〔`RLimit64`・`SockaddrNl`・`PollFd`・`StatFs`・`MountAttr`・`SockFprog`〕と `SyscallNumber`・`BpfInstruction` のサイズ、関数 33 件・`sendfile` の型〔`off_t *`・`size_t`・`ssize_t`。#2759〕）、`sys/seccomp_notify.rs` の `libc_abi`（構造体 5 種〔`SeccompData`・`SeccompNotif`・`SeccompNotifResp`・`IoVec`・`Ucred`〕と gnu の `MsgHdr`・`CmsgHdr`、関数 5 件）、`sys/macos.rs`（関数 5 件〔`geteuid`・`fsync`、`plugin_fs` の可変長 `openat`・`fcntl` と `fstatat`〕と `plugin_fs` の構造体 `Stat`〔64 bit inode 版の `libc::stat` とサイズ・配置を照合。x86_64 の `fstatat$INODE64` の `link_name` は型で検査できない。#3096〕）で、いずれも `const` 評価。構造体は `size_of`・`align_of` とフィールドのオフセット、関数は同じ関数ポインタ型への自前と `libc` の代入で照合する。対象外と扱い（理由は `libc_abi` の doc）は次のとおり。

- 対象外（`libc` 0.2.189 に対応物が無い）: `CapUserHeader`・`CapUserData`（capability.h）、`LandlockRulesetAttr`・`LandlockPathBeneathAttr`（landlock.h。サイズとオフセットは実行時の試験が照合）、`sys/bpf.rs` の `BpfProgLoadAttr`・`BpfProgAttachAttr`・`BpfProgQueryAttr`（`union bpf_attr`。bpf.h）、`ControlBuf`・`SendControlBuf`（バイトの入れ物。`cmsghdr` への整列だけ確認）。macOS の `acl_*` 6 件は `libc` の apple に宣言が無く未照合（SDK の `sys/acl.h` との照合は #2369 から未了）
- 型の綴りの違いで ABI は同じ: `prlimit` の `resource`（自前 `i32`・`libc` は `c_uint`。自前を `u32` に揃えるかはオーナー判断で `sys` の本体は変えていない）、`syscall` の第 1 引数（`SyscallNumber` は `repr(transparent)` の `i64`。`size_of`・`align_of` で `c_long` と照合）、`SockFprog.filter` の `*const`（`libc` は `*mut`）、自前の構造体を指すポインタ（`fstatfs`・`sendto`・`recvfrom`・`poll`・`prlimit`・`sendmsg`・`recvmsg`。ポインタ先の型を別々に書き、構造体の同一性は構造体の照合が保証する）
- 一部だけの照合: `StatFs.f_flags` は gnu の `libc::statfs` で非公開の `f_spare` の先頭にあるため、gnu に限り `f_frsize` のオフセット + 1 語（80）で照合。`BpfInstruction` は `seccomp` の非公開フィールドのため `libc::sock_filter` とサイズ・アラインメントだけ。`SockaddrNl.nl_pad` は `nl_family` の直後で代替
- gnu に限る（musl は core を CI でビルドしないため未照合。「musl の扱い（#3103）」参照）: `ioctl`・`prlimit`・`renameat2`、`MsgHdr`・`CmsgHdr`（musl は `size_t` でなく `int` / `socklen_t` と非公開のパディング）
- 値をわざとずらして評価が失敗することを、`MountAttr` のフィールド順の入れ替え（x86_64 で E0080）と `kill` の期待型の変更（aarch64 で E0308）で確認した（ずらした変更はコミットしていない）

crates/platform-macos の対象外（理由は照合モジュールのコメント）: FFI でない安全なラッパー群、`MFSTYPENAMELEN`（`libc` に無い。`libc::statfs` の `f_fstypename` と `f_mntonname` のオフセット差で間接照合）、`statfs` の `link_name`（自前は `x86_64`、`libc` は `not(aarch64)` と書き方が違うが、親の `compile_error!` で 2 アーキに限るため同じシンボルになる）。`geteuid` は macOS と Linux の両方でコンパイルされるため、PR の ubuntu CI でもネイティブに評価される。

crates/supervisor（#1840）は `src/sys/linux.rs` の `libc_abi`（最上位と `control_ffi` の子）で、LP64 の x86_64・aarch64 に限って照合する。宣言 `syscall` と利用経路（capget / capset / execveat / close_range）に加え、`prctl` の宣言・`PR_*` 定数と各ラッパー（#3202）も同じ cfg に限り（非 LP64 は `Unsupported`、`close_fds_from` は `/proc/self/fd` のみ。#3100・SUP-6）、照合の cfg と宣言の cfg を揃える。`libc` は `cfg(target_os = "linux")` の dev-dependencies。対象外（`libc` に対応物が無い）: `LINUX_CAPABILITY_VERSION_3`・`CapUserHeader`・`CapUserData`・`XATTR_NAME_CAPS`・`FILE_CAPS_BUF_LEN`、FFI でない上限（`MAX_EXEC_VECTOR`・`CAP_NUMBER_LIMIT`）、非 LP64 の `arch`（値が `None`）。`PR_CAP_AMBIENT_RAISE` 等は `u64`、`AT_EMPTY_PATH` は `i64` のため、`libc` の `c_int` を広げて比べる。関数内の `listen` やリテラルの errno（`SIGKILL`・`EINVAL`・`ENOSYS`・`EBADF`）は項目として参照できないため、型の代入と `libc` の値の固定で照合する。`connect` の第 2 引数は自前が `c_void`、`libc` が `sockaddr` を指すポインタで ABI は同じ（`SockaddrUn` のレイアウトは別に照合）。

crates/gpu（#2979・#2980 で `sys` を新設）は未適用。照合は #1837 の子 #2989 で行う。dev-dependencies の `libc`（=0.2.189）だけを使い、追加には oci（#2590）と同様に crate ごとのオーナー承認が要る。

なお rustdoc は dev-dependencies を解決しないため、`#[cfg(test)]` の外のドキュメントコメントから `libc::…` へ intra-doc リンクを張らない（バッククォートのみ。#1300）。

crates/guest-init（#2076）は `src/sys.rs` の試験専用モジュール `libc_abi` で照合する（`libc` は `cfg(target_os = "linux")` の dev-dependencies。`Cargo.lock` は guest-init の `dependencies` に `libc` が 1 行増えるだけで `[[package]]` は増えない。製品の静的バイナリの依存は不変）。照合したのは定数 6 件（`MS_RDONLY`・`MS_NOSUID`・`MS_NODEV`・`MS_NOEXEC`・`O_NOCTTY`・`ENOSYS`）、`cstring` 内のリテラル EINVAL（22）の値の固定 1 件、`mount` の型（自前と `libc` を同じ関数ポインタ型へ代入）1 件。libc 0.2.189 では値も宣言も x86_64・aarch64 の gnu と musl で同一なので `target_env` では分けず、`SUPPORTED` と同じ LP64（x86_64・aarch64）に限る。`O_NOCTTY` の値も x86_64・aarch64 の cfg に閉じる（対象外 arch は 0。#3202）。musl は aarch64 のみ `cross-target-check` で評価され（x86_64 musl は CI に無いが値は同一）、対象外は `SUPPORTED`・`PSEUDO_STRICT`・`DEVTMPFS_FLAGS`・`virtiofs_flags`（方針値。組み合わせは固定値テストが見る）・安全なラッパー群。値のずらし（`MS_NODEV` を 5 に。x86_64 gnu と aarch64 musl で E0080）と型のずらし（期待型を `c_uint` に。E0308）で評価が失敗することを確認した（ずらした変更はコミットしていない）。
