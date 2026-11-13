# macOS ゲストカーネル（arm64）の設定とビルド

macOS の VM（Virtualization.framework）で起動するゲスト Linux カーネルの、設定フラグメントとビルドスクリプトです（TASK-64 追補・#1874・MAC-1・MS-5）。
カーネルは kernel.org の LTS を自前でビルドする方針（#362）で、アーキテクチャは arm64（Apple Silicon）のみです（#1823 の決定）。x86_64（Intel）は実機確認の要否が決まってから追加します。

カーネルのバイナリはコミットしません。実ビルドと release への添付は人間担当で、Agent は実行していません（**実ビルドは未検証**）。

## GPL-2.0 のソース提供に要る材料

Linux カーネルは GPL-2.0 です。ソース提供の義務は、次の材料を公開することで満たす方針です（#362）。

| 材料 | 場所 |
| ---- | ---- |
| tarball の URL・版・sha256 | [`source.lock`](source.lock)（版 6.18.57、`https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.57.tar.xz`） |
| 設定 | [`arm64-guest.config`](arm64-guest.config)（Kconfig フラグメント）と、ビルドが出力する完全な `config` |
| ビルドスクリプト | [`build.sh`](build.sh) |

- ビルドが出力する `config`（生成された `.config`）と `build-info.txt`（版・URL・sha256・ツールチェーン・ホスト・ビルド識別情報の固定値）を、カーネルの Image と一緒に配布物へ添えます
- release への添付とアセット説明の文言（「Linux kernel（GPL-2.0）」）は人間担当です
- Kata Containers・apple/containerization の設定行は写していません。必要なオプションは自前で列挙しています（#1823）

## 版の決め方

`https://www.kernel.org/releases.json` の `moniker` が `longterm` で最も新しい系列を選びました（決定基準日は #1823 の 2026-10-12、固定した日は 2026-10-16 で、その日の最新の longterm は 6.18 系の 6.18.57）。
sha256 は同じ版のディレクトリの署名付き `sha256sums.asc` から写しています（tarball を取得して自分でハッシュを取る方式は使っていません）。

- **署名の検証は未確認**です。人間が `https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc` を kernel.org の署名鍵で `gpg --verify` し、`linux-6.18.57.tar.xz` の行が `source.lock` と一致することを確かめてください
- tarball 自体の PGP 署名検証はスクリプトに入れていません（今後の課題）。fail-closed の門は `source.lock` の sha256 です
- 版を上げるときは、`source.lock` の 3 行を同じ手順で更新します。longterm の更新への追随（脆弱性の修正）も同じ手順です

## ビルドするホストと必要なツール

- 推奨: Linux。arm64 のネイティブ、または x86_64 から `CROSS_COMPILE=aarch64-linux-gnu-` か `LLVM=1` でのクロスビルド
- macOS 上のビルドは**未確認**です（自己テストは macOS の BSD ツールでも回しますが、カーネル本体のビルドは試していません）
- Windows は非対応です（`unsupported-os` で終了コード 2）
- ツール: make・gcc（aarch64）または clang/lld（`LLVM=1`）・flex・bison・bc・perl・curl・tar・xz・sha256sum（または shasum）
- root は要りません。`sudo` も `make install` も使いません

## 使い方

```bash
make guest-kernel-build            # target/guest-kernel/<版>/arm64/ に出力
guest/kernel/build.sh --output-dir /path/to/out --jobs 8 --cross-compile aarch64-linux-gnu-
guest/kernel/build.sh --tarball /path/to/linux-6.18.57.tar.xz   # 取得済みの tarball も同じ sha256 で照合
```

| 引数 | 環境変数 | 内容 |
| ---- | -------- | ---- |
| `--output-dir <dir>` | `GUEST_KERNEL_OUTPUT_DIR` | 既定 `target/guest-kernel/<版>/arm64`。空または未存在のディレクトリのみ |
| `--tarball <path>` | `GUEST_KERNEL_TARBALL` | 取得済みの tarball を使う |
| `--jobs N` | `GUEST_KERNEL_JOBS` | 1〜256 |
| `--cross-compile <prefix>` | `CROSS_COMPILE` | 文字種は `[A-Za-z0-9._/+-]` |
| `--llvm` | `LLVM=1` | clang/lld を使う |
| `--fetch-timeout S` | | 既定 900、1〜3600 |
| `--extract-timeout S` | | 既定 600、1〜3600 |
| `--build-timeout S` | | 既定 7200、1〜21600（make 1 回あたり） |

出力は `Image`（非圧縮）・`config`・`build-info.txt` です。成功時は stdout に `Image` のパスを 1 行出します。

| 終了コード | 意味 | エラーコードの例 |
| ---------- | ---- | ---------------- |
| 0 | 成功 | |
| 1 | ビルドの失敗 | `build-failed`・`config-option-missing` |
| 2 | 引数・環境・ツール未導入・出力先・ロック・アーカイブの不正、Windows | `unsupported-os`・`output-exists`・`bad-lock`・`unsafe-archive-entry` |
| 3 | 期限切れ | `fetch-timeout`・`extract-timeout`・`build-timeout` |
| 4 | 完全性の検証失敗（ビルドしない） | `checksum-mismatch` |

自己テストは `make guest-kernel-build-selftest` です（スタブの tar.xz・コンパイラ・curl のみ。取得も実ビルドもしません）。`make ci` と CI は取得も実ビルドも行いません。

## 設定の方針

arm64 の `defconfig` は大量のドライバを含み、`CONFIG_MODULES=n` にすると `m` が `y` に昇格して巨大になるため、`allnoconfig` にフラグメントを重ねる最小構成にしています。
Kconfig は依存が満たされない記号を黙って落とすので、`build.sh` は `olddefconfig` の後に、フラグメントで `=y` とした全記号が `.config` に残ったかを照合し、欠けていれば `config-option-missing` で失敗します。
各オプションを有効にする理由は、フラグメントの各行の直前のコメントにあります。主なものは次のとおりです。

| 区分 | 記号 | 理由 |
| ---- | ---- | ---- |
| モジュール | `MODULES` 無効 | init（#1875）はモジュールをロードせず、initrd（#1878）は init だけを梱包するため、すべて組み込みにする |
| initramfs | `BLK_DEV_INITRD`・`RD_GZIP` | `FANDHE_CONTAINER_MACOS_VM_INITRD` で渡す initramfs（圧縮形式は gzip の newc。`scripts/build-guest-initrd.sh`〔#1878〕が `init` 1 個だけの gzip 圧縮 cpio を作るため前提どおり） |
| /dev | `DEVTMPFS`・`DEVTMPFS_MOUNT` | `/dev` の供給 |
| namespace | `NAMESPACES`・`USER_NS`・`PID_NS`・`NET_NS`・`UTS_NS`・`IPC_NS`（`SYSVIPC`・`POSIX_MQUEUE`） | ゲスト内のコンテナ分離（MAC-4・TASK-191・#2276）。rootless は `USER_NS`（SEC-5・CORE-6） |
| cgroup v2 | `CGROUPS`・`MEMCG`・`CGROUP_SCHED`・`FAIR_GROUP_SCHED`・`CFS_BANDWIDTH`・`CGROUP_PIDS`・`BLK_CGROUP`・`BLK_DEV_THROTTLING`・`BLK_CGROUP_IOCOST` | memory・cpu・pids・io の 4 controller（`memory.max`・`cpu.weight`/`cpu.max`・`pids.max`・`io.max`/`io.weight`。#4658 の委譲対象。CORE-4） |
| seccomp | `SECCOMP`・`SECCOMP_FILTER` | CORE-5。user notification も使える |
| Landlock | `SECURITY`・`SECURITY_LANDLOCK`・`CONFIG_LSM="landlock"` | core は ABI 6 以上を要し、6.18 で満たす。`CONFIG_LSM` に名前が無いと起動時に無効になるため明示する（文字列の記号は残存照合の対象外で、自己テストの静的検査で守る） |
| 転送 | `PCI`・`PCI_HOST_GENERIC`・`VIRTIO_PCI`・`VIRTIO_MMIO` | VZ の arm64 が virtio を PCI と MMIO のどちらで出すかが未確認のため両方 |
| コンソール | `VIRTIO_CONSOLE` | `console=hvc0`、`vm_boot` のブートマーカー |
| ブロック | `BLOCK`・`VIRTIO_BLK` | `FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE` |
| virtio-fs | `FUSE_FS`・`VIRTIO_FS` | `virtiofs_io`（タグ `fandhe-io`）と #1374 |
| vsock | `NET`・`VSOCKETS`・`VIRTIO_VSOCKETS` | ホストとゲストの制御経路（MAC-1） |
| virtio-gpu | `DRM`・`DRM_VIRTIO_GPU` | GPU-6 と `poc/vz-custom-virtio-gpu/guest/check-virtio-gpu.sh` |
| 協調停止 | `INPUT`・`INPUT_EVDEV`・`INPUT_KEYBOARD`・`KEYBOARD_GPIO`・`GPIOLIB`・`GPIO_PL061` | VZ の `requestStop`（仮想 power button）を evdev の `KEY_POWER` にして guest-init の停止を始める（MAC-4・#2270）。実 VM での到達と実ビルドでの脱落有無は未確認（#1628・#2282） |
| 乱数 | `HW_RANDOM`・`HW_RANDOM_VIRTIO` | VZ のエントロピーデバイス。不要と判断したら外す |

意図して入れない記号（#2276）: `MEMCG_V1`・`CPUSETS_V1`（cgroups v2 単独。CORE-4・SEC-6。自己テストで =y が無いことを照合）、`CPUSETS`（委譲対象の 4 controller に無い）、`TIME_NS`（core が `CLONE_NEWTIME` を使わない）、`BPF_SYSCALL`・`CGROUP_BPF`（rootless ではデバイス cgroup の eBPF を適用しない。攻撃面を増やさない）、`SWAP`（ゲストに swap デバイスが無い。`memory.swap.max` は無ければ fail-closed）。

init（#1875）への申し送り: `DEVTMPFS_MOUNT` は initramfs 起動には効かないため、init が自分で `/dev` を mount する必要があります。
`DEVTMPFS_MOUNT` が効く起動（initramfs の `/init` を使わずディスクの root から起動し、カーネルが `/dev` を先に mount する場合）でも、既存のマウントポイントへの重ね掛けは許されるため、init の devtmpfs の mount は通常 `EBUSY` にならず、新規 mount として成功します（`classify_dev_mount` は Fresh を返し、既存 mount の検査は通りません）。init の mount が実際に `EBUSY` を受けた場合に限り、init は `/proc` の mount 後に mountinfo で `/dev` が `devtmpfs` かつ `nosuid`・`noexec` であることを確かめ、満たさなければ `stage=dev errno=16` を出して `READY_MARKER` を出さずに止まります（[`init.rs`](../../crates/guest-init/src/init.rs) の `classify_dev_mount`・`verify_existing_dev`、検査は [`mountinfo.rs`](../../crates/guest-init/src/mountinfo.rs) の `check_dev_hardened`。#2139）。本構成は `DEVTMPFS_SAFE` を有効にしておらずカーネルの自動 mount に `nosuid`・`noexec` が付かないため、`EBUSY` を受けた場合のこの経路では止まります（自動 mount 済みでも重ね掛けが成功すれば止まりません。現行の initramfs 起動では `EBUSY` の分岐に入りません）。

## 未確認事項

- VZ の arm64 で使われる virtio の転送方式（PCI か MMIO か）。#1628 で確定する
- VZ が非圧縮の `Image` を要するか（gzip 圧縮を受け付けるか）
- ディスクイメージのファイルシステム（`EXT4_FS` 等は `FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE` の形式が決まるまで入れていない）
- macOS ホストでのビルド
- `sha256sums.asc` の署名検証の実施有無（上記）
- 設定フラグメントがこの版で全記号を残すか（実ビルドで確認。結果は #1628 へ）
- namespace・cgroup v2・seccomp・Landlock の記号は #2276 で足した。実ビルドで全記号が残るか、実 VM で動くかは未検証（#1628・#2282 で確かめる）
- ゲスト内のコンテナ実行に要る残りの記号（`OVERLAY_FS`・`UNIX`・`INET`・`AUDIT`）は未追加（#4749 で扱う。`docs/design/macos-vm-strategy.md`）

## 実ビルドの記録

実ビルドの結果（Image のサイズ・所要時間・ホストの OS）は #1628 に記録します。Agent は実ビルドを実行していません。

## ビルド識別情報（#4590・MAC-1・REPAIR-3）

- kbuild は既定でビルド環境のユーザー名・ホスト名・ビルド時刻を `Linux version ...` の行と `/proc/version` に埋め込みます。この行はゲストのコンソールログに出るため、public の issue へ貼ると環境の名前が漏れます
- `build.sh` は `KBUILD_BUILD_USER=fandhe-container`・`KBUILD_BUILD_HOST=build`・`KBUILD_BUILD_TIMESTAMP=1970-01-01 00:00:00 UTC` を常に make へ渡します。呼び出し元の環境に同名の変数があっても使わず（警告を出して無視）、上書きの引数もありません。値を変えるときはスクリプトの定数を直します
- 固定値は `build-info.txt` の末尾 3 行（`kbuild_build_user`・`kbuild_build_host`・`kbuild_build_timestamp`）に残ります
- この変更より前にビルドした Image には実際の名前が残っています。ログを貼る前に作り直してください。`strings Image | grep 'Linux version'` で確認できます
- 本スクリプト以外の方法でビルドした Image も、上の 3 変数を指定しなければ名前が入ります
- macOS の BSD `date` では、initramfs の mtime の固定だけが効きません（`Linux version` の行の固定は効きます）
- 実カーネルのビルドでの確認は未検証です（#1628）
