//! 分離違反の試行を拒否したときの構造化された違反記録（SEC-4 の記録経路。TASK-27.2・#134）。
//!
//! # 役割と範囲
//!
//! `crate::exec` の各拒否経路（`plan` / `plan_rootful_host_root` / `isolate` 系の前提、
//! `MountIsolation::establish` の前提、`mount_proc` の証跡不一致・パス検証・shared 伝播、
//! `prepare_rootfs` / `pivot_root` の証跡不一致・rootfs パス検証・shared 伝播。TASK-27.3・#135、
//! `setns` 参加前の exec の対象の検証〔種別 `exec_target`。入れ子の PID 1 でない・cgroup 不一致・呼び出し側と
//! 同じ pid / mnt namespace。SUP-6・SEC-1・TASK-163.1・#500〕、`setns` 参加後の root の照合〔同種別。参加後の
//! `/` が記録したコンテナの rootfs でない。SUP-6・SEC-1・TASK-163.3・#502〕）は、
//! 拒否時に [`IsolationViolation`] を `ExecError::violation` に載せて呼び出し側へ返す。
//!
//! **本モジュールは記録の経路のみを提供する。** マウント層の違反から `Mount` 監査イベントへの
//! 写像は [`IsolationViolation::mount_audit_event`]（TASK-41.4・#195）、exec の対象の拒否から `ExecTarget`
//! 監査イベントへの写像は [`IsolationViolation::exec_audit_event`]（SUP-6・TASK-163 追補・#1465）で実装済み。
//! エントリポイント検証の拒否（種別 `entrypoint` の 8 理由。launch と exec の子が共有する）から `Entrypoint`
//! 監査イベントへの写像は [`IsolationViolation::entrypoint_audit_event`]（SEC-4・SUP-6・SEC-1・TASK-163 追補・#1595）。
//! supervisor の exec の worker が返し得る違反（[`ViolationReason::EXEC_WORKER_REASONS`]。種別 `exec_target` の 10 理由、
//! 種別 `rootfs_pivot` の `rootfs_is_host_root`、bundle の rootfs の固定が運ぶ種別 `mount_target` の
//! `path_symlink_or_not_directory`・`path_missing`）から監査イベントへの写像は [`ViolationReason::exec_worker_audit_event`]
//! （`exec_target` は `ExecTarget`、他の 3 理由は `mount_audit_event` と同じ `Mount` のパスなし・理由コードつき。#1614 の事後監査・#1702）。
//! ファイルへの永続化（TASK-41.5.1・#839）とカーネル監査フォールバック（#840）も `audit_log` に実装済みで、
//! 本モジュールの記録を実際の sink へ流す本番経路（launcher・CLI への配線）は未実装
//! （REPAIR-3: 実装済みを装わない）。launch 経路の pivot 前段の失敗は、子が状態 pipe で理由を親へ返し親が
//! `exec::record_launch_mount_rejection` で記録する入口まで実装済み（`exec/launch_status.rs`。#1815）で、
//! 本番 launcher からの呼び出しは未実装（Phase B）。
//!
//! # 違反とシステムエラーの区別
//!
//! - **違反**: 呼び出し側の構成・呼び出し文脈・パスが分離の前提を満たさず、fail-closed で
//!   拒否したもの（例: User なしの既定計画、PID 1 でない呼び出し、rootfs 外のマウント先、
//!   shared 伝播上のマウント先）。`ExecError::violation` は `Some`
//! - **システムエラー**: 前提は満たしているが、カーネル・procfs の応答が得られない・解釈
//!   できない、または syscall が失敗したもの（例: `ENOMEM`・`/proc` の読み取り失敗・
//!   mountinfo の書式不正・`unshare` の `EPERM`）。`ExecError::violation` は `None`
//! - **保護の適用不能**（種別 `protected_path_apply`。SEC-2・SEC-4・#2013）: `readonly_paths`・`masked_paths` の段で、
//!   対象を固定して検査を通った後に、保護を載せる操作（bind・`mount_setattr`・`open_tree`・`move_mount`・tmpfs のマウント）
//!   と事後検証が失敗したもの。失敗の原因が環境（古いカーネル〔`ENOSYS`〕・LSM）か rootfs の内容（イメージが置いた対象の
//!   種別・マウント状態）かを、untrusted な子に頼る親は判別できない。SEC-4 は記録漏れを許さず、保護が載らないまま
//!   起動を拒否した痕跡はこの記録だけになるため、違反の試行として記録する。理由トークンは対象の検査の拒否と分け
//!   （`readonly_path_apply_failed`・`masked_path_apply_failed`）、受け手が区別できるようにする。`ExecError::code` は
//!   errno 由来の分類を保つ。マウント前のシステムエラー（`fstat`・`dup`・mountinfo の読み取り失敗・定数定義の不正）は
//!   従来どおり違反なしの失敗で記録しない
//! - hostname の書式不正（`Hostname::new`）は入力値の書式エラーであり、分離違反の試行では
//!   ないため違反記録を付けない
//!
//! # 秘匿
//!
//! 違反記録には namespace の識別子（`mnt:[inode]` 等）や正規化後のホスト側実パスを含めない。
//! 対象（[`ViolationSubject`]）は呼び出し側が渡したパスだけで、長さを上限で切り詰め、
//! Cc・Cf・Zl・Zp の文字とバックスラッシュをエスケープして保持する。
//!
//! exec 対象の監査イベントは理由コード（静的トークン）だけを持ち、対象パス（期待 cgroup パス等）も
//! 載せない（`AuditEvent::ExecTarget` がパスのフィールドを持たない型で保証する。#1465）。
//! エントリポイントの監査イベントも同様に理由コードだけを持つ（`AuditEvent::Entrypoint`。#1595）。
//!
//! # `target_moved`（種別 `mount_target`）の扱い（#1595）
//!
//! `target_moved` の発生源は `mount_proc_at_dir`・`exec/inject.rs`・`exec/tmpfs.rs`・`exec/bind_mounts.rs`（#1913）の 4 箇所で、いずれも
//! launch 経路の `pivot_root` の前にある。稼働中コンテナへの exec の子（`prepare_exec_child` /
//! `exec_checked_entrypoint`・インタプリタ検証・封印コピー）では生じず、supervisor の worker の結果行にも
//! 載らない。そのため exec 側の記録（`Entrypoint` / `ExecTarget`）の対象外で、launch 側では
//! `exec::audit_mount_violation`（`Mount` イベント）で記録する（本番 launcher から結線済み。子の失敗理由は状態 pipe で親へ運ばれ、親が `exec::record_launch_mount_rejection` で記録する。#1815・#1816）。

use std::path::Path;

use crate::audit_log::{AuditEvent, AuditPath, AuditReason};
use crate::sanitize::is_display_unsafe_char;
use crate::traits::types::ErrorCode;

use super::IsolationStage;

/// 違反の種別（どの検査で拒否したか）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ViolationKind {
    /// 分離計画（`plan` / `plan_rootful_host_root`）または `isolate` 系の実行前検証。
    PlanRejected,
    /// `MountIsolation::establish` の前提（PID 1・入れ子・シングルスレッド・新しい mount ns）。
    EstablishPrecondition,
    /// `mount_proc` 直前の証跡の再検証（PID 1・mount ns・PID ns の不一致）。
    EvidenceMismatch,
    /// `mount_proc` のマウント先パスの検証（rootfs 境界・symlink・`..` 等）。
    MountTarget,
    /// `mount_proc` のマウント先または `prepare_rootfs` の rootfs が shared propagation 上にある。
    SharedPropagation,
    /// `prepare_rootfs` の rootfs 指定そのものの拒否（ホスト root の指定・固定後の移動。TASK-27.3）。
    RootfsPivot,
    /// exec 直前のエントリポイントの検証（ランタイム自身のホスト側バイナリの指定等。TASK-27.4.1）。
    Entrypoint,
    /// 稼働中コンテナへの exec の対象（pid1）の検証（`setns` 参加前の対象の検証と、参加後の root の照合。
    /// SUP-6・SEC-1・TASK-163.1・TASK-163.3）。
    ExecTarget,
    /// 読み取り専用化・覆い（`readonly_paths`・`masked_paths` の段）の適用そのものの失敗。対象の検査を通った後に
    /// 保護を載せる操作（bind・`mount_setattr`・tmpfs のマウント等）と事後検証が失敗したもので、環境起因
    /// （古いカーネル・LSM）と rootfs の内容起因を親が区別できないため、違反の試行として記録する
    /// （SEC-4・SEC-2・TASK-41 追補・#2013）。
    ProtectedPathApply,
}

impl ViolationKind {
    /// 機械可読な種別名（snake_case）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlanRejected => "plan_rejected",
            Self::EstablishPrecondition => "establish_precondition",
            Self::EvidenceMismatch => "evidence_mismatch",
            Self::MountTarget => "mount_target",
            Self::SharedPropagation => "shared_propagation",
            Self::RootfsPivot => "rootfs_pivot",
            Self::Entrypoint => "entrypoint",
            Self::ExecTarget => "exec_target",
            Self::ProtectedPathApply => "protected_path_apply",
        }
    }
}

/// 違反の理由コード。種別・ビヘイビア ID・`ErrorCode`・段・英語メッセージは理由から一意に
/// 決まる（拒否経路ごとに文字列を手で組まない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ViolationReason {
    /// namespace が 1 つも選ばれていない。
    NoNamespaces,
    /// hostname 指定があるのに UTS namespace が無い（ホストの hostname を書き換え得る）。
    HostnameWithoutUts,
    /// PID namespace があるのに mount namespace が無い。
    PidWithoutMount,
    /// 既定計画に user namespace が無い（SEC-5）。
    UserNamespaceRequired,
    /// 既定計画で euid / egid 0 をそのまま写そうとした（SEC-5）。
    HostRootIdentityMapping,
    /// rootful 計画に user namespace が含まれる。
    RootfulWithUserNamespace,
    /// rootful 計画 / 実行が euid 0 でない。
    RootfulRequiresRoot,
    /// 既定計画の作成後に実効 uid / gid が変わった（SEC-5）。
    IdentityChanged,
    /// establish の呼び出し元が PID 1 でない。
    EstablishNotPid1,
    /// establish 時の `NSpid` 末尾が 1 でない。
    EstablishNspidNotPid1,
    /// establish 時に入れ子の PID namespace にいない。
    EstablishNotNestedPidNamespace,
    /// establish 時にマルチスレッドである。
    EstablishMultiThreaded,
    /// `unshare(CLONE_NEWNS)` の前後で mount namespace が変わらなかった。
    EstablishMountNamespaceNotFresh,
    /// `mount_proc` の呼び出し元が PID 1 でない（`getpid`）。
    EvidenceCallerNotPid1,
    /// `mount_proc` 呼び出し時の `NSpid` 末尾が 1 でない。
    EvidenceNspidNotPid1,
    /// 呼び出しスレッドの mount namespace が証跡と異なる。
    EvidenceMountNamespaceMismatch,
    /// 呼び出しスレッドの PID namespace が証跡と異なる。
    EvidencePidNamespaceMismatch,
    /// rootfs / マウント先が絶対パスでない。
    PathNotAbsolute,
    /// rootfs / マウント先が NUL を含む。
    PathContainsNul,
    /// rootfs / マウント先が `..` を含む。
    PathParentComponent,
    /// マウント先が rootfs 配下でない。
    TargetOutsideRootfs,
    /// rootfs が存在しない。
    RootfsMissing,
    /// rootfs 自体または祖先に symlink・非ディレクトリがある。
    RootfsSymlinkOrNotDirectory,
    /// マウント先が rootfs そのもの。
    TargetIsRootfs,
    /// 経路上に symlink または非ディレクトリがある。
    PathSymlinkOrNotDirectory,
    /// 経路上の要素が存在しない。
    PathMissing,
    /// マウント先が shared propagation 上にある。
    TargetOnSharedMount,
    /// fd で固定した後にマウント先が改名・移動・削除された。
    TargetMoved,
    /// bind mount の元の経路（中間要素または末端）に symlink がある。symlink は辿らず拒否する
    /// （TASK-29 追補・#1913。SEC-1・CORE-1）。
    BindSourceSymlink,
    /// bind mount の元がディレクトリでも通常ファイルでもない（FIFO・ソケット・デバイス等。#1913。SEC-1）。
    BindSourceUnsupportedType,
    /// bind mount の元を起動を依頼した利用者の権限で読めない（#1913。SEC-1）。
    BindSourceNotAccessible,
    /// bind mount の元が rootfs 自身またはその祖先である（#1913。SEC-1）。
    BindSourceContainsRootfs,
    /// bind mount の元（または配下のマウント）が状態ストアのルートに到達する。適用の段が固定した元に対して判定する（#1915。SEC-1）。
    BindSourceReachesStateRoot,
    /// bind mount の元（または `rbind` で公開される配下のマウント）が procfs・sysfs などの疑似 FS 上にある。
    /// 適用の段が固定した fd の `fstatfs` の `f_type` と、付け替えた木の mountinfo の fstype で判定する（#2098・#2065 案 B。SEC-1）。
    BindSourcePseudoFs,
    /// bind mount 先の既存の種別が元と合わない（ディレクトリと通常ファイルの取り違え等。#1913。SEC-1）。
    BindTargetKindMismatch,
    /// Landlock の適用時に、Mount 由来のルールの対象のマウント ID（`mnt_id`）が、pivot 前段が載せた直後に記録した
    /// ものと違う（記録後にマウントが差し替えられた。CORE-5・SEC-1・SEC-4・#2071）。
    LandlockMountIdentityMismatch,
    /// Landlock の適用時に、Mount 由来のルールの対象がマウントのルートでない（マウントの内側のディレクトリを
    /// 指している。CORE-5・SEC-1・SEC-4・#2071）。
    LandlockMountNotRoot,
    /// Landlock の適用時に、祖先の書き込み権を VFS の読み取り専用属性で打ち消すはずのルール（検証済みの `ro` の bind）の
    /// 対象のマウントが、実際には読み取り専用でない（CORE-5・SEC-1・SEC-4・#1917）。
    LandlockMountNotReadOnly,
    /// rootless の基本デバイスノードの bind 元（ホストの `/dev/<名前>`）が、期待する文字デバイスではない
    /// （symlink・通常ファイル・ディレクトリ、または `rdev` が固定表と違う）。bind せずに拒否する
    /// （TASK-29 追補・#1660。CORE-6・SEC-5）。
    HostDeviceNodeUnexpected,
    /// rootfs が `/`（ホスト root）そのもの。ホスト root への pivot は無意味かつ危険なため拒否する。
    RootfsIsHostRoot,
    /// rootfs が shared propagation 上にある（pivot_root は EINVAL になり、bind もホストへ伝播し得る）。
    RootfsOnSharedMount,
    /// fd で固定した後に rootfs が改名・移動・削除された。
    RootfsMoved,
    /// rootfs の bind mount が rootfs 配下の既存マウント（サブマウント）を複製した。許可リストは
    /// 空のため 1 つでもあれば拒否する（ホスト領域への bind mount 経由の脱出を防ぐ）。
    RootfsHasSubmounts,
    /// rootfs 内のファイルが rootfs の外にもハードリンクを持つ（外部 inode を共有する）。pivot 後の
    /// 書き込みが rootfs 外のファイルを書き換えるため拒否する。
    RootfsHasExternalHardlink,
    /// エントリポイントがランタイム自身の実行ファイル（`/proc/self/exe`）と同一の inode
    /// （CVE-2019-5736 型の多層防御。TASK-27.4.1）。
    EntrypointIsRuntimeBinary,
    /// 新 root の `/dev/null` が文字デバイス 1:3 でない（symlink・通常ファイル・別のデバイスノードへ差し替え
    /// られている。SUP-6・SEC-1・TASK-163 追補・#1459）。コンテナは `CAP_MKNOD` で自分の `/dev/null` を差し替え
    /// られるため、標準入出力の置換先として開く前に検証し、差し替え先を開かずに拒否する。
    StdioNullNotNullDevice,
    /// エントリポイントのインタープリタ（シェバンの連鎖・ELF の `PT_INTERP`）が、ランタイム自身の実行ファイルと
    /// 同一の inode に解決される（`#!/proc/self/exe` 等。CVE-2019-5736 型。SUP-6・SEC-1・CORE-5・TASK-163 追補・
    /// #1458）。カーネルはインタープリタを exec するプロセス自身の文脈で開くため、本体の照合
    /// （[`Self::EntrypointIsRuntimeBinary`]）だけでは通ってしまう。
    EntrypointInterpreterIsRuntimeBinary,
    /// 新 root の `/dev` が実ディレクトリでない（symlink・通常ファイル等へ差し替えられている。SUP-6・SEC-1・
    /// SEC-4・TASK-163 追補・#1459）。`/dev/null` を別の木から引かせないため、symlink を辿らずに拒否する。
    ExecDevNotDirectory,
    /// 新 root の `/proc` が procfs でない（symlink・非ディレクトリ・別のファイルシステムが置かれている。SUP-6・
    /// SEC-1・SEC-4・TASK-163 追補・#1459）。ランタイムの同一性の基準と、検証済みの fd の開き直しの起点を
    /// すり替えさせないために拒否する。
    ExecProcNotProcfs,
    /// エントリポイントの封印した複製の元のサイズが上限（`MAX_SEALED_COPY_BYTES`）を超える（SUP-6・SEC-1・
    /// SEC-4・TASK-163 追補・#1531）。照合した内容をそのまま実行するための複製をメモリ（memfd）に作るため、
    /// 巨大なファイルは作らず拒否する（コンテナ側が巨大なファイルを置いて exec ごとの確保を強いる DoS を防ぐ）。
    EntrypointCopyTooLarge,
    /// エントリポイントの封印した複製の封印（`F_SEAL_SEAL|SHRINK|GROW|WRITE` = 0x0F ちょうど）を確認できない
    /// （封印の追加・取得の失敗、開き直した fd の seal が 0x0F でない。SUP-6・SEC-1・SEC-4・TASK-163 追補・
    /// #1531）。書き込み可能な複製を実行すると照合と実行の内容がずれるため、実行せず拒否する（fail-closed）。
    EntrypointCopySealUnverified,
    /// エントリポイントが `noexec` のマウント上にある（`fstatfs` の `ST_NOEXEC`。SUP-6・SEC-1・SEC-4・
    /// TASK-163 追補・#1531）。封印した複製（memfd）は内部マウント上にあるため、`execveat` が元のファイルの
    /// マウントで行う `noexec` の拒否が働かない。マウントの `noexec` を複製で迂回させないため、複製せずに拒否する。
    EntrypointOnNoexecMount,
    /// exec の対象が入れ子の PID namespace の PID 1 でない（`NSpid` が 2 要素・末尾 1 でない。SUP-6）。
    ExecTargetNotNestedPid1,
    /// exec の対象の所属 cgroup が、記録から導いた期待パスと一致しない（pid 再利用・移動。SEC-1）。
    ExecTargetCgroupMismatch,
    /// exec の対象が呼び出し側と同じ PID namespace にいる（参加しても分離境界を越えない対象。SUP-6）。
    ExecTargetSharesPidNamespace,
    /// exec の対象が呼び出し側と同じ mount namespace にいる（同上）。
    ExecTargetSharesMountNamespace,
    /// exec の対象と呼び出し側の user namespace が、`open` で関係を記録した時点から変わった（SUP-6・SEC-5・
    /// TASK-163.4・TASK-163.h2・#1462）。別の user namespace にいる対象へは user namespace にも参加する設計
    /// （rootless の exec）だが、参加する集合は `open` で判定した関係から決めるため、検証から参加までの間に対象
    /// が別の user namespace へ移った、または呼び出し側の user namespace が変わった場合は、`setns` が成功する
    /// 場合でも参加の前に拒否する（誤った集合で参加すると、user namespace に入らないまま mount / PID namespace
    /// へ参加し、呼び出し側の資格情報のまま動いて launch より強い権限になり得る）。
    ExecTargetInOtherUserNamespace,
    /// `setns` 参加後の呼び出しプロセスの `/` が、記録（bundle の `config.json`）から固定したコンテナの
    /// rootfs と同じディレクトリでない（pivot していない対象・`/` へ別のマウントが重ねられた対象。この状態で
    /// 制限を適用するとルールが別の木に付き、コマンドも rootfs の外で動く。SEC-1・TASK-163.3）。
    ExecRootNotContainerRootfs,
    /// `setns` 参加後の呼び出しプロセスの user namespace または mount namespace が、制限を準備した時点の exec の
    /// 対象（pid1）のものと一致しない（user namespace は #1462 で追加。参加した user namespace が対象のものである
    /// ことの照合）（A 用に準備した制限を、同じ rootfs を共有する別コンテナ B へ参加した
    /// プロセスへ適用させない。rootfs のディレクトリ照合だけでは取り違えを検出できない。SEC-1・TASK-163.4）。
    ExecJoinedNamespaceMismatch,
    /// `setns` 参加後に子が入る PID namespace（`ns/pid_for_children`）が、制限を準備した時点の exec の対象
    /// （pid1）の PID namespace と一致しない（同じ mount namespace を共有する別の参加先へ、準備済みの制限を
    /// 適用させない。SEC-1・TASK-163.4）。
    ExecJoinedPidNamespaceMismatch,
    /// cgroup 参加後の呼び出しプロセスの所属 cgroup が、制限を準備した時点の exec の対象のコンテナ cgroup と
    /// 一致しない（同上。SEC-1・TASK-163.4）。
    ExecJoinedCgroupMismatch,
    /// 起動時から保持する pidfd の指すプロセスが、記録した pid と一致しない（pidfd の取り違え・記録の
    /// 古さ。cgroup の所属に依らない同一性の照合。SUP-6・SEC-1・TASK-163 追補・#1461）。
    ExecTargetPidfdMismatch,
    /// 読み取り専用にするパス（固定集合または `config.json` 由来）の保護を載せる操作・事後検証が失敗した
    /// （SEC-2・SEC-4・TASK-41 追補・#2013）。対象の検査（symlink・shared・移動）の拒否は含まない。
    ReadonlyPathApplyFailed,
    /// 覆うパス（固定集合または `config.json` 由来）の保護を載せる操作・事後検証が失敗した
    /// （SEC-2・SEC-4・TASK-41 追補・#2013）。
    MaskedPathApplyFailed,
    /// `/sys` の sysfs（`mounts[]` の sysfs）を読み取り専用で供給する操作・事後検証が失敗した（新しい sysfs・
    /// ホスト `/sys` の ro rbind・配下に rw のマウントが残る等の事後条件違反。対象の検査〔symlink・shared〕の
    /// 拒否は含まない。SEC-2・SEC-4・OCI-4・#2020）。
    SysfsApplyFailed,
}

impl ViolationReason {
    /// 種別 [`ViolationKind::ProtectedPathApply`] の理由の全一覧（読み取り専用化・覆い・sysfs の適用失敗。SEC-2・SEC-4）。
    ///
    /// 親は段つきの許可リスト（`launch_status`）で、`readonly_paths` 段には `ReadonlyPathApplyFailed` だけ、
    /// `masked_paths` 段には `MaskedPathApplyFailed` だけ、`mount_sysfs` 段には `SysfsApplyFailed` だけを通す。理由の集合の唯一の定義。
    pub(super) const PROTECTED_PATH_APPLY_REASONS: [Self; 3] = [
        Self::ReadonlyPathApplyFailed,
        Self::MaskedPathApplyFailed,
        Self::SysfsApplyFailed,
    ];

    /// 種別 [`ViolationKind::ExecTarget`] の理由の全一覧（exec の対象の拒否。SUP-6・SEC-1）。
    ///
    /// supervisor の worker が返す理由コードを許可リストとして引き直すための SSOT（#1465）。
    pub const EXEC_TARGET_REASONS: [ViolationReason; 10] = [
        Self::ExecTargetNotNestedPid1,
        Self::ExecTargetCgroupMismatch,
        Self::ExecTargetSharesPidNamespace,
        Self::ExecTargetSharesMountNamespace,
        Self::ExecTargetInOtherUserNamespace,
        Self::ExecRootNotContainerRootfs,
        Self::ExecJoinedNamespaceMismatch,
        Self::ExecJoinedPidNamespaceMismatch,
        Self::ExecJoinedCgroupMismatch,
        Self::ExecTargetPidfdMismatch,
    ];

    /// 種別 [`ViolationKind::Entrypoint`] の理由の全一覧（エントリポイント検証の拒否。SEC-4・SUP-6・SEC-1）。
    ///
    /// supervisor の worker が返す `SetupFailed` の理由コードを許可リストとして引き直すための SSOT（#1595）。
    pub const ENTRYPOINT_REASONS: [ViolationReason; 8] = [
        Self::EntrypointIsRuntimeBinary,
        Self::EntrypointInterpreterIsRuntimeBinary,
        Self::StdioNullNotNullDevice,
        Self::ExecDevNotDirectory,
        Self::ExecProcNotProcfs,
        Self::EntrypointCopyTooLarge,
        Self::EntrypointCopySealUnverified,
        Self::EntrypointOnNoexecMount,
    ];

    /// エントリポイント検証の理由コード文字列から理由を引き直す（許可リスト照合。未知の文字列は `None`）。
    ///
    /// worker の結果行から届いた文字列を、監査レコードへ入る静的トークンへ変換する唯一の入口（#1595）。
    pub fn from_entrypoint_token(token: &str) -> Option<Self> {
        Self::ENTRYPOINT_REASONS
            .into_iter()
            .find(|r| r.as_str() == token)
    }

    /// エントリポイント検証の理由なら `Entrypoint` 監査イベントを返す（それ以外は `None`）。パスは持たない。
    pub fn entrypoint_audit_event(self) -> Option<AuditEvent> {
        (self.kind() == ViolationKind::Entrypoint).then(|| AuditEvent::Entrypoint {
            reason: AuditReason::new(self.as_str()),
        })
    }

    /// exec 対象の理由コード文字列から理由を引き直す（許可リスト照合。未知の文字列は `None`）。
    ///
    /// 外部（worker の結果行）から届いた文字列を、監査レコードへ入る静的トークンへ変換する唯一の入口。
    pub fn from_exec_target_token(token: &str) -> Option<Self> {
        Self::EXEC_TARGET_REASONS
            .into_iter()
            .find(|r| r.as_str() == token)
    }

    /// exec 対象の理由なら `ExecTarget` 監査イベントを返す（それ以外は `None`）。パスは持たない。
    pub fn exec_target_audit_event(self) -> Option<AuditEvent> {
        (self.kind() == ViolationKind::ExecTarget).then(|| AuditEvent::ExecTarget {
            reason: AuditReason::new(self.as_str()),
        })
    }

    /// exec の worker（supervisor が core の `spawn_exec_worker` で fork し、対象の特定から制限の再適用・コマンドの
    /// fork までを行うプロセス）が `ExecError::violation` として返し得る理由の全一覧（SEC-4・SUP-6・SEC-1）。
    ///
    /// supervisor の親プロセスが worker の結果行（`err` 行）の `<種別>/<理由>` を引き直す許可リストの SSOT。
    /// [`Self::EXEC_TARGET_REASONS`] の 10 理由と、`prepare_exec_restrictions` の `reject_own_root` が返す
    /// 種別 `rootfs_pivot` の `rootfs_is_host_root`（worker 自身の `/` が bundle の rootfs と同じディレクトリ）、
    /// bundle の rootfs の固定（`oci_runtime::RootfsDir::pin`）が検証後の差し替えで拒否する種別 `mount_target` の
    /// `path_symlink_or_not_directory`・`path_missing`（`RootfsPinError` が運ぶ。#1702）、Landlock の再適用が
    /// `NotRecorded` でも行う読み取り専用属性の照合の拒否（種別 `mount_target` の `landlock_mount_not_read_only`。
    /// `ro` の bind の属性が失われた・観測できない場合。CORE-5・SEC-1・SEC-4・#1917）から成る。
    /// 一覧と worker の経路のソースが作る理由の一致は `exec/violation_scan.rs` の単体テストが固定する。
    /// exec の子が `execve` 前に報告する違反（種別 `entrypoint`）は `ok` 行の `SetupFailed` で運ばれるためここに含めない。
    pub const EXEC_WORKER_REASONS: [ViolationReason; 14] = [
        Self::ExecTargetNotNestedPid1,
        Self::ExecTargetCgroupMismatch,
        Self::ExecTargetSharesPidNamespace,
        Self::ExecTargetSharesMountNamespace,
        Self::ExecTargetInOtherUserNamespace,
        Self::ExecRootNotContainerRootfs,
        Self::ExecJoinedNamespaceMismatch,
        Self::ExecJoinedPidNamespaceMismatch,
        Self::ExecJoinedCgroupMismatch,
        Self::ExecTargetPidfdMismatch,
        Self::RootfsIsHostRoot,
        Self::PathSymlinkOrNotDirectory,
        Self::PathMissing,
        Self::LandlockMountNotReadOnly,
    ];

    /// worker の結果行の種別名 `kind` と理由コード `reason` から理由を引き直す（許可リスト照合。SEC-4・SUP-6）。
    ///
    /// [`Self::EXEC_WORKER_REASONS`] にあり、かつ種別名がその理由の種別と一致するときだけ `Some`。未知の理由・
    /// 一覧外の理由・種別の食い違いは `None`（呼び出し側は記録せず fail-closed で扱う）。外部（worker の結果行）から
    /// 届いた文字列を、監査レコードへ入る静的トークンへ変換する唯一の入口。
    pub fn from_exec_worker_token(kind: &str, reason: &str) -> Option<Self> {
        Self::EXEC_WORKER_REASONS
            .into_iter()
            .find(|r| r.as_str() == reason && r.kind().as_str() == kind)
    }

    /// worker の経路の拒否 1 件に対応する監査イベント（SEC-4・SUP-6・SEC-1）。
    ///
    /// [`Self::EXEC_WORKER_REASONS`] の理由だけが対象で、それ以外は `None`。種別 `exec_target` は
    /// [`Self::exec_target_audit_event`] と同じ `ExecTarget`、種別 `rootfs_pivot` は
    /// [`IsolationViolation::mount_audit_event`] と同じ層 `Mount` へ写す（理由コードだけを持つ呼び出し側のため
    /// パスなし・理由コードつき。#1701）。種別 `mount_target`（bundle の rootfs の固定の差し替え検出。#1702）も同じ。1 理由が写る層は 1 つだけ（二重に記録しない）。
    pub fn exec_worker_audit_event(self) -> Option<AuditEvent> {
        if !Self::EXEC_WORKER_REASONS.contains(&self) {
            return None;
        }
        match self.kind() {
            ViolationKind::ExecTarget => self.exec_target_audit_event(),
            ViolationKind::RootfsPivot | ViolationKind::MountTarget => {
                self.mount_layer_audit_event(None)
            }
            _ => None,
        }
    }

    /// `ViolationReason` の全 variant（pivot 前段の失敗を親が引き直す元。SEC-4・CORE-1・TASK-29 追補・#1815）。
    ///
    /// 手書きの理由リストを別に持たず、種別（[`Self::kind`]）で絞って使う（[`Self::from_launch_token`]）。
    /// 足し忘れは単体テスト（`ALL` の件数が `as_str` の分岐数と一致すること）が検出する。
    pub(super) const ALL: [ViolationReason; 65] = [
        Self::NoNamespaces,
        Self::HostnameWithoutUts,
        Self::PidWithoutMount,
        Self::UserNamespaceRequired,
        Self::HostRootIdentityMapping,
        Self::RootfulWithUserNamespace,
        Self::RootfulRequiresRoot,
        Self::IdentityChanged,
        Self::EstablishNotPid1,
        Self::EstablishNspidNotPid1,
        Self::EstablishNotNestedPidNamespace,
        Self::EstablishMultiThreaded,
        Self::EstablishMountNamespaceNotFresh,
        Self::EvidenceCallerNotPid1,
        Self::EvidenceNspidNotPid1,
        Self::EvidenceMountNamespaceMismatch,
        Self::EvidencePidNamespaceMismatch,
        Self::PathNotAbsolute,
        Self::PathContainsNul,
        Self::PathParentComponent,
        Self::TargetOutsideRootfs,
        Self::RootfsMissing,
        Self::RootfsSymlinkOrNotDirectory,
        Self::TargetIsRootfs,
        Self::PathSymlinkOrNotDirectory,
        Self::PathMissing,
        Self::TargetOnSharedMount,
        Self::TargetMoved,
        Self::BindSourceSymlink,
        Self::BindSourceUnsupportedType,
        Self::BindSourceNotAccessible,
        Self::BindSourceContainsRootfs,
        Self::BindSourceReachesStateRoot,
        Self::BindSourcePseudoFs,
        Self::BindTargetKindMismatch,
        Self::LandlockMountIdentityMismatch,
        Self::LandlockMountNotRoot,
        Self::LandlockMountNotReadOnly,
        Self::HostDeviceNodeUnexpected,
        Self::RootfsIsHostRoot,
        Self::RootfsOnSharedMount,
        Self::RootfsMoved,
        Self::RootfsHasSubmounts,
        Self::RootfsHasExternalHardlink,
        Self::EntrypointIsRuntimeBinary,
        Self::StdioNullNotNullDevice,
        Self::EntrypointInterpreterIsRuntimeBinary,
        Self::ExecDevNotDirectory,
        Self::ExecProcNotProcfs,
        Self::EntrypointCopyTooLarge,
        Self::EntrypointCopySealUnverified,
        Self::EntrypointOnNoexecMount,
        Self::ExecTargetNotNestedPid1,
        Self::ExecTargetCgroupMismatch,
        Self::ExecTargetSharesPidNamespace,
        Self::ExecTargetSharesMountNamespace,
        Self::ExecTargetInOtherUserNamespace,
        Self::ExecRootNotContainerRootfs,
        Self::ExecJoinedNamespaceMismatch,
        Self::ExecJoinedPidNamespaceMismatch,
        Self::ExecJoinedCgroupMismatch,
        Self::ExecTargetPidfdMismatch,
        Self::ReadonlyPathApplyFailed,
        Self::MaskedPathApplyFailed,
        Self::SysfsApplyFailed,
    ];

    /// pivot 前段の子が状態 pipe で運んだ理由コード `token` から理由を引き直す（許可リスト照合。SEC-4・#1815）。
    ///
    /// 種別が `mount_target`・`shared_propagation`・`rootfs_pivot`・`establish_precondition`・`evidence_mismatch`
    /// のどれかである理由だけが `Some`（pivot 前段の各段が返し得る違反の種別）。それ以外・未知の文字列は `None`
    /// （呼び出し側は違反なしの失敗として扱う）。子は untrusted なので、文字列を監査レコードへ入る静的トークンへ
    /// 変換する唯一の入口になる。
    pub(super) fn from_launch_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| {
            r.as_str() == token
                && matches!(
                    r.kind(),
                    ViolationKind::MountTarget
                        | ViolationKind::SharedPropagation
                        | ViolationKind::RootfsPivot
                        | ViolationKind::EstablishPrecondition
                        | ViolationKind::EvidenceMismatch
                )
        })
    }

    /// launch 経路で子が運んだ理由に対応する `Mount` 監査イベント（パスなし・理由コードつき。SEC-4・#1815）。
    ///
    /// 対象は `MountTarget`・`SharedPropagation`・`RootfsPivot`・`ProtectedPathApply`（[`IsolationViolation::mount_audit_event`] と同じ範囲）。
    /// 子から無制限長のパスを運ばないため、パスは載せない。
    ///
    /// 加えて、bind mount の段（`MountBinds`）が user namespace 由来で拒否した 2 理由
    /// （[`Self::MOUNT_BINDS_USER_NAMESPACE_REASONS`]。SEC-5・#2072）も同じ形で写す。共有の写像
    /// （`mount_layer_audit_event`）は広げないため、`plan()` 時点の拒否や worker の経路の記録は変わらない。
    pub(super) fn launch_mount_audit_event(self) -> Option<AuditEvent> {
        if let Some(event) = self.mount_layer_audit_event(None) {
            return Some(event);
        }
        if Self::MOUNT_BINDS_USER_NAMESPACE_REASONS.contains(&self) {
            return Some(AuditEvent::Mount {
                path: None,
                reason: Some(AuditReason::new(self.as_str())),
            });
        }
        None
    }

    /// bind mount の段（`PrePivotStep::MountBinds`）が user namespace の状態で拒否する理由（SEC-5・SEC-4・#2072）。
    /// 種別は `PlanRejected` のため [`Self::from_launch_token`] は通さず、`launch_status` が段 `mount_binds` と
    /// 組のときだけ追加で受ける。理由の集合の唯一の定義。
    pub(super) const MOUNT_BINDS_USER_NAMESPACE_REASONS: [Self; 2] =
        [Self::UserNamespaceRequired, Self::HostRootIdentityMapping];

    /// launch の Landlock 段（`ExecPhaseStep::Landlock`）が `E` 行で運ぶ、Mount 由来のルールの照合の違反の 3 理由
    /// （SEC-1・SEC-4・CORE-5・#2130）。種別は `MountTarget` だが、他の段では受けないため
    /// [`Self::from_launch_token`] には入れず、`launch_status` が段 `landlock` と組のときだけ引き直す。
    /// 理由の集合の唯一の定義（`from_landlock_apply_kind` の分岐との一致は単体テストが固定する）。
    pub(super) const LANDLOCK_APPLY_REASONS: [Self; 3] = [
        Self::LandlockMountIdentityMismatch,
        Self::LandlockMountNotRoot,
        Self::LandlockMountNotReadOnly,
    ];

    /// launch の Landlock 段の `E` 行の理由コード `token` から理由を引き直す（許可リスト照合。untrusted な子の入力）。
    pub(super) fn from_landlock_apply_token(token: &str) -> Option<Self> {
        Self::LANDLOCK_APPLY_REASONS
            .into_iter()
            .find(|r| r.as_str() == token)
    }

    /// launcher の `plan()` が拒否した理由（種別 `PlanRejected`）を、launch 経路で記録する `Mount` 監査イベントへ
    /// 写す（パスなし・理由コードつき。SEC-4・SEC-1・#2130）。他の種別は `None`。
    ///
    /// [`Self::mount_layer_audit_event`] は `PlanRejected` を記録しない（#2109 の判断。exec の worker の経路が
    /// 共有するため広げない）。launch の計画の拒否は launcher が親として直接記録するので、専用の写像に分ける。
    pub(super) fn launch_plan_audit_event(self) -> Option<AuditEvent> {
        (self.kind() == ViolationKind::PlanRejected).then(|| AuditEvent::Mount {
            path: None,
            reason: Some(AuditReason::new(self.as_str())),
        })
    }

    /// マウント層（`MountTarget`・`SharedPropagation`・`RootfsPivot`）の理由なら、理由コードつきの
    /// `Mount` 監査イベントを返す。それ以外の種別は `None`（#1701）。
    ///
    /// [`IsolationViolation::mount_audit_event`]（パスあり/なし）と worker の経路
    /// （[`Self::exec_worker_audit_event`]。パスなし）が共有する写像の唯一の実装。
    fn mount_layer_audit_event(self, path: Option<AuditPath>) -> Option<AuditEvent> {
        match self.kind() {
            ViolationKind::MountTarget
            | ViolationKind::SharedPropagation
            | ViolationKind::RootfsPivot
            | ViolationKind::ProtectedPathApply => Some(AuditEvent::Mount {
                path,
                reason: Some(AuditReason::new(self.as_str())),
            }),
            ViolationKind::PlanRejected
            | ViolationKind::EstablishPrecondition
            | ViolationKind::EvidenceMismatch
            | ViolationKind::Entrypoint
            | ViolationKind::ExecTarget => None,
        }
    }

    /// Landlock 適用の失敗の種別から、対応する違反理由を引く（Mount 由来のルールの識別子の照合の違反だけ。
    /// 他は分離違反の試行ではないため `None`。CORE-5・SEC-4・#2071）。
    ///
    /// 識別子の照合（`MountIdentityMismatch`・`MountNotRoot`）は launch 経路（`MountCheck::Recorded`）でのみ生じる。exec の
    /// 再適用（worker の経路）は `NotRecorded` で照合しないため、これらは `EXEC_WORKER_REASONS` に含めない。
    /// `MountNotReadOnly` は `NotRecorded` でも生じるため含める（#1917）。
    pub(super) fn from_landlock_apply_kind(
        kind: &crate::landlock::LandlockApplyErrorKind,
    ) -> Option<Self> {
        use crate::landlock::LandlockApplyErrorKind as K;
        match kind {
            K::MountIdentityMismatch { .. } => Some(Self::LandlockMountIdentityMismatch),
            K::MountNotRoot { .. } => Some(Self::LandlockMountNotRoot),
            K::MountNotReadOnly { .. } => Some(Self::LandlockMountNotReadOnly),
            _ => None,
        }
    }

    /// 機械可読な理由コード（snake_case）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoNamespaces => "no_namespaces",
            Self::HostnameWithoutUts => "hostname_without_uts",
            Self::PidWithoutMount => "pid_without_mount",
            Self::UserNamespaceRequired => "user_namespace_required",
            Self::HostRootIdentityMapping => "host_root_identity_mapping",
            Self::RootfulWithUserNamespace => "rootful_with_user_namespace",
            Self::RootfulRequiresRoot => "rootful_requires_root",
            Self::IdentityChanged => "identity_changed",
            Self::EstablishNotPid1 => "establish_not_pid1",
            Self::EstablishNspidNotPid1 => "establish_nspid_not_pid1",
            Self::EstablishNotNestedPidNamespace => "establish_not_nested_pid_namespace",
            Self::EstablishMultiThreaded => "establish_multi_threaded",
            Self::EstablishMountNamespaceNotFresh => "establish_mount_namespace_not_fresh",
            Self::EvidenceCallerNotPid1 => "evidence_caller_not_pid1",
            Self::EvidenceNspidNotPid1 => "evidence_nspid_not_pid1",
            Self::EvidenceMountNamespaceMismatch => "evidence_mount_namespace_mismatch",
            Self::EvidencePidNamespaceMismatch => "evidence_pid_namespace_mismatch",
            Self::PathNotAbsolute => "path_not_absolute",
            Self::PathContainsNul => "path_contains_nul",
            Self::PathParentComponent => "path_parent_component",
            Self::TargetOutsideRootfs => "target_outside_rootfs",
            Self::RootfsMissing => "rootfs_missing",
            Self::RootfsSymlinkOrNotDirectory => "rootfs_symlink_or_not_directory",
            Self::TargetIsRootfs => "target_is_rootfs",
            Self::PathSymlinkOrNotDirectory => "path_symlink_or_not_directory",
            Self::PathMissing => "path_missing",
            Self::TargetOnSharedMount => "target_on_shared_mount",
            Self::TargetMoved => "target_moved",
            Self::BindSourceSymlink => "bind_source_symlink",
            Self::BindSourceUnsupportedType => "bind_source_unsupported_type",
            Self::BindSourceNotAccessible => "bind_source_not_accessible",
            Self::BindSourceContainsRootfs => "bind_source_contains_rootfs",
            Self::BindSourceReachesStateRoot => "bind_source_reaches_state_root",
            Self::BindSourcePseudoFs => "bind_source_pseudo_fs",
            Self::BindTargetKindMismatch => "bind_target_kind_mismatch",
            Self::LandlockMountIdentityMismatch => "landlock_mount_identity_mismatch",
            Self::LandlockMountNotRoot => "landlock_mount_not_root",
            Self::LandlockMountNotReadOnly => "landlock_mount_not_read_only",
            Self::HostDeviceNodeUnexpected => "host_device_node_unexpected",
            Self::RootfsIsHostRoot => "rootfs_is_host_root",
            Self::RootfsOnSharedMount => "rootfs_on_shared_mount",
            Self::RootfsMoved => "rootfs_moved",
            Self::RootfsHasSubmounts => "rootfs_has_submounts",
            Self::RootfsHasExternalHardlink => "rootfs_has_external_hardlink",
            Self::EntrypointIsRuntimeBinary => "entrypoint_is_runtime_binary",
            Self::StdioNullNotNullDevice => "stdio_null_not_null_device",
            Self::EntrypointInterpreterIsRuntimeBinary => {
                "entrypoint_interpreter_is_runtime_binary"
            }
            Self::ExecDevNotDirectory => "exec_dev_not_directory",
            Self::ExecProcNotProcfs => "exec_proc_not_procfs",
            Self::EntrypointCopyTooLarge => "entrypoint_copy_too_large",
            Self::EntrypointCopySealUnverified => "entrypoint_copy_seal_unverified",
            Self::EntrypointOnNoexecMount => "entrypoint_on_noexec_mount",
            Self::ExecTargetNotNestedPid1 => "exec_target_not_nested_pid1",
            Self::ExecTargetCgroupMismatch => "exec_target_cgroup_mismatch",
            Self::ExecTargetSharesPidNamespace => "exec_target_shares_pid_namespace",
            Self::ExecTargetSharesMountNamespace => "exec_target_shares_mount_namespace",
            Self::ExecTargetInOtherUserNamespace => "exec_target_in_other_user_namespace",
            Self::ExecRootNotContainerRootfs => "exec_root_not_container_rootfs",
            Self::ExecJoinedNamespaceMismatch => "exec_joined_namespace_mismatch",
            Self::ExecJoinedPidNamespaceMismatch => "exec_joined_pid_namespace_mismatch",
            Self::ExecJoinedCgroupMismatch => "exec_joined_cgroup_mismatch",
            Self::ExecTargetPidfdMismatch => "exec_target_pidfd_mismatch",
            Self::ReadonlyPathApplyFailed => "readonly_path_apply_failed",
            Self::MaskedPathApplyFailed => "masked_path_apply_failed",
            Self::SysfsApplyFailed => "sysfs_apply_failed",
        }
    }

    /// 違反の種別。
    pub fn kind(self) -> ViolationKind {
        match self {
            Self::NoNamespaces
            | Self::HostnameWithoutUts
            | Self::PidWithoutMount
            | Self::UserNamespaceRequired
            | Self::HostRootIdentityMapping
            | Self::RootfulWithUserNamespace
            | Self::RootfulRequiresRoot
            | Self::IdentityChanged => ViolationKind::PlanRejected,
            Self::EstablishNotPid1
            | Self::EstablishNspidNotPid1
            | Self::EstablishNotNestedPidNamespace
            | Self::EstablishMultiThreaded
            | Self::EstablishMountNamespaceNotFresh => ViolationKind::EstablishPrecondition,
            Self::EvidenceCallerNotPid1
            | Self::EvidenceNspidNotPid1
            | Self::EvidenceMountNamespaceMismatch
            | Self::EvidencePidNamespaceMismatch => ViolationKind::EvidenceMismatch,
            Self::PathNotAbsolute
            | Self::PathContainsNul
            | Self::PathParentComponent
            | Self::TargetOutsideRootfs
            | Self::RootfsMissing
            | Self::RootfsSymlinkOrNotDirectory
            | Self::TargetIsRootfs
            | Self::PathSymlinkOrNotDirectory
            | Self::PathMissing
            | Self::TargetMoved
            | Self::BindSourceSymlink
            | Self::BindSourceUnsupportedType
            | Self::BindSourceNotAccessible
            | Self::BindSourceContainsRootfs
            | Self::BindSourceReachesStateRoot
            | Self::BindSourcePseudoFs
            | Self::BindTargetKindMismatch
            | Self::LandlockMountIdentityMismatch
            | Self::LandlockMountNotRoot
            | Self::LandlockMountNotReadOnly
            | Self::HostDeviceNodeUnexpected => ViolationKind::MountTarget,
            Self::TargetOnSharedMount | Self::RootfsOnSharedMount => {
                ViolationKind::SharedPropagation
            }
            Self::RootfsIsHostRoot
            | Self::RootfsMoved
            | Self::RootfsHasSubmounts
            | Self::RootfsHasExternalHardlink => ViolationKind::RootfsPivot,
            Self::EntrypointIsRuntimeBinary
            | Self::StdioNullNotNullDevice
            | Self::EntrypointInterpreterIsRuntimeBinary
            | Self::ExecDevNotDirectory
            | Self::ExecProcNotProcfs
            | Self::EntrypointCopyTooLarge
            | Self::EntrypointCopySealUnverified
            | Self::EntrypointOnNoexecMount => ViolationKind::Entrypoint,
            Self::ExecTargetNotNestedPid1
            | Self::ExecTargetCgroupMismatch
            | Self::ExecTargetSharesPidNamespace
            | Self::ExecTargetSharesMountNamespace
            | Self::ExecTargetInOtherUserNamespace
            | Self::ExecRootNotContainerRootfs
            | Self::ExecJoinedNamespaceMismatch
            | Self::ExecJoinedPidNamespaceMismatch
            | Self::ExecJoinedCgroupMismatch
            | Self::ExecTargetPidfdMismatch => ViolationKind::ExecTarget,
            Self::ReadonlyPathApplyFailed
            | Self::MaskedPathApplyFailed
            | Self::SysfsApplyFailed => ViolationKind::ProtectedPathApply,
        }
    }

    /// 違反した前提のビヘイビア ID（SSOT: spec `04-behavior/`）。
    pub fn behavior_id(self) -> &'static str {
        match self {
            Self::UserNamespaceRequired
            | Self::HostRootIdentityMapping
            | Self::IdentityChanged
            | Self::HostDeviceNodeUnexpected => "SEC-5",
            Self::ExecTargetCgroupMismatch
            | Self::StdioNullNotNullDevice
            | Self::EntrypointInterpreterIsRuntimeBinary
            | Self::ExecDevNotDirectory
            | Self::ExecProcNotProcfs
            | Self::EntrypointCopyTooLarge
            | Self::EntrypointCopySealUnverified
            | Self::EntrypointOnNoexecMount
            | Self::ExecRootNotContainerRootfs
            | Self::ExecJoinedNamespaceMismatch
            | Self::ExecJoinedPidNamespaceMismatch
            | Self::ExecJoinedCgroupMismatch
            | Self::BindSourceSymlink
            | Self::BindSourceUnsupportedType
            | Self::BindSourceNotAccessible
            | Self::BindSourceContainsRootfs
            | Self::BindSourceReachesStateRoot
            | Self::BindSourcePseudoFs
            | Self::BindTargetKindMismatch => "SEC-1",
            Self::LandlockMountIdentityMismatch
            | Self::LandlockMountNotRoot
            | Self::LandlockMountNotReadOnly => "CORE-5",
            Self::ReadonlyPathApplyFailed
            | Self::MaskedPathApplyFailed
            | Self::SysfsApplyFailed => "SEC-2",
            Self::ExecTargetNotNestedPid1
            | Self::ExecTargetSharesPidNamespace
            | Self::ExecTargetSharesMountNamespace
            | Self::ExecTargetInOtherUserNamespace
            | Self::ExecTargetPidfdMismatch => "SUP-6",
            _ => "CORE-1",
        }
    }

    /// 呼び出し側へ返す `ErrorCode`（構成・パスの不正は `InvalidArgument`、実行文脈・権限の
    /// 前提違反は `FailedPrecondition`）。
    pub fn error_code(self) -> ErrorCode {
        match self {
            Self::NoNamespaces
            | Self::HostnameWithoutUts
            | Self::PidWithoutMount
            | Self::UserNamespaceRequired
            | Self::RootfulWithUserNamespace
            | Self::PathNotAbsolute
            | Self::PathContainsNul
            | Self::PathParentComponent
            | Self::TargetOutsideRootfs
            | Self::RootfsMissing
            | Self::RootfsSymlinkOrNotDirectory
            | Self::TargetIsRootfs
            | Self::PathSymlinkOrNotDirectory
            | Self::PathMissing
            | Self::BindSourceSymlink
            | Self::BindSourceUnsupportedType
            | Self::BindSourceContainsRootfs
            | Self::BindSourceReachesStateRoot
            | Self::BindSourcePseudoFs
            | Self::BindTargetKindMismatch
            | Self::RootfsIsHostRoot => ErrorCode::InvalidArgument,
            Self::BindSourceNotAccessible => ErrorCode::PermissionDenied,
            Self::HostRootIdentityMapping
            | Self::RootfulRequiresRoot
            | Self::IdentityChanged
            | Self::EstablishNotPid1
            | Self::EstablishNspidNotPid1
            | Self::EstablishNotNestedPidNamespace
            | Self::EstablishMultiThreaded
            | Self::EstablishMountNamespaceNotFresh
            | Self::EvidenceCallerNotPid1
            | Self::EvidenceNspidNotPid1
            | Self::EvidenceMountNamespaceMismatch
            | Self::EvidencePidNamespaceMismatch
            | Self::TargetOnSharedMount
            | Self::TargetMoved
            | Self::HostDeviceNodeUnexpected
            | Self::LandlockMountIdentityMismatch
            | Self::LandlockMountNotRoot
            | Self::LandlockMountNotReadOnly
            | Self::RootfsOnSharedMount
            | Self::RootfsMoved
            | Self::RootfsHasSubmounts
            | Self::RootfsHasExternalHardlink
            | Self::ExecTargetNotNestedPid1
            | Self::ExecTargetCgroupMismatch
            | Self::ExecTargetSharesPidNamespace
            | Self::ExecTargetSharesMountNamespace
            | Self::ExecTargetInOtherUserNamespace
            | Self::ExecRootNotContainerRootfs
            | Self::ExecJoinedNamespaceMismatch
            | Self::ExecJoinedPidNamespaceMismatch
            | Self::ExecJoinedCgroupMismatch
            | Self::ExecTargetPidfdMismatch
            | Self::ExecDevNotDirectory
            | Self::ExecProcNotProcfs
            | Self::EntrypointCopySealUnverified
            | Self::ReadonlyPathApplyFailed
            | Self::MaskedPathApplyFailed
            | Self::SysfsApplyFailed => ErrorCode::FailedPrecondition,
            Self::EntrypointIsRuntimeBinary
            | Self::StdioNullNotNullDevice
            | Self::EntrypointInterpreterIsRuntimeBinary
            | Self::EntrypointCopyTooLarge
            | Self::EntrypointOnNoexecMount => ErrorCode::PermissionDenied,
        }
    }

    /// 拒否した段の既定（計画は `Validate`、rootfs 指定は `PrepareRootfs`、エントリポイントは `Exec`、
    /// exec の対象は `SetNs`、それ以外は `MountProc`）。
    /// `prepare_rootfs` / `pivot_root` が共通のパス理由を返すときは、呼び出した段を
    /// `ExecError::from_violation_at` で明示する。
    pub(super) fn stage(self) -> IsolationStage {
        match self.kind() {
            ViolationKind::PlanRejected => IsolationStage::Validate,
            ViolationKind::RootfsPivot => IsolationStage::PrepareRootfs,
            ViolationKind::Entrypoint => IsolationStage::Exec,
            ViolationKind::ExecTarget => IsolationStage::SetNs,
            ViolationKind::ProtectedPathApply => match self {
                Self::MaskedPathApplyFailed => IsolationStage::MountMaskedPaths,
                Self::SysfsApplyFailed => IsolationStage::MountSysfs,
                _ => IsolationStage::MountReadonlyPaths,
            },
            _ => IsolationStage::MountProc,
        }
    }

    /// 英語のメッセージ（`ExecError::message`）。マウント先に関する文言は procfs（`mount_proc`）と tmpfs
    /// （`mount_tmpfs`。SUP-12・TASK-169.2）の両方の段が使うため、種別を含めない中立な表現にする。
    pub fn message(self) -> &'static str {
        match self {
            Self::NoNamespaces => "at least one namespace must be selected",
            Self::HostnameWithoutUts => "hostname requires the UTS namespace",
            Self::PidWithoutMount => "the PID namespace requires the mount namespace",
            Self::UserNamespaceRequired => {
                "the user namespace is required to map container root to an unprivileged host ID"
            }
            Self::HostRootIdentityMapping => {
                "refusing identity mapping of host root into the user namespace \
                 (map a subordinate ID range from /etc/subuid and /etc/subgid instead; \
                 subordinate ID mapping is not implemented yet, see TASK-40)"
            }
            Self::RootfulWithUserNamespace => {
                "the rootful host-root plan must not include the user namespace"
            }
            Self::RootfulRequiresRoot => "the rootful host-root plan requires euid 0",
            Self::IdentityChanged => "effective uid/gid changed after the plan was created",
            Self::EstablishNotPid1 => {
                "not PID 1; call from the first child created after unshare(CLONE_NEWPID)"
            }
            Self::EstablishNspidNotPid1 | Self::EvidenceNspidNotPid1 => {
                "NSpid does not end with 1; not PID 1 of the innermost PID namespace"
            }
            Self::EstablishNotNestedPidNamespace => {
                "not in a nested PID namespace; isolate with Namespace::Pid first"
            }
            Self::EstablishMultiThreaded => {
                "the process must be single-threaded before establishing mount isolation"
            }
            Self::EstablishMountNamespaceNotFresh => {
                "unshare(CLONE_NEWNS) did not move the thread to a new mount namespace"
            }
            Self::EvidenceCallerNotPid1 => {
                "mount_proc must be called by PID 1 of the isolated PID namespace"
            }
            Self::EvidenceMountNamespaceMismatch => {
                "isolation evidence does not belong to the current mount namespace"
            }
            Self::EvidencePidNamespaceMismatch => {
                "isolation evidence does not belong to the current PID namespace"
            }
            Self::PathNotAbsolute => "rootfs and mount target must be absolute paths",
            Self::PathContainsNul => "rootfs and mount target must not contain NUL",
            Self::PathParentComponent => "rootfs and mount target must not contain '..'",
            Self::TargetOutsideRootfs => "mount target must be under rootfs",
            Self::RootfsMissing => "rootfs must exist",
            Self::RootfsSymlinkOrNotDirectory => {
                "rootfs and its ancestors must be directories, not symlinks"
            }
            Self::TargetIsRootfs => {
                "mount target must be a dedicated directory below rootfs, not rootfs itself"
            }
            Self::PathSymlinkOrNotDirectory => {
                "mount target path components must be directories, not symlinks"
            }
            Self::PathMissing => "mount target path must exist",
            Self::TargetOnSharedMount => {
                "mount target is on a shared mount; isolate the mount namespace first"
            }
            Self::TargetMoved => "mount target was moved or removed after validation",
            Self::BindSourceSymlink => "bind mount source path components must not be symlinks",
            Self::BindSourceUnsupportedType => {
                "bind mount source must be a directory or a regular file"
            }
            Self::BindSourceNotAccessible => {
                "bind mount source is not readable with the privileges of the requesting user"
            }
            Self::BindSourceContainsRootfs => {
                "bind mount source must not be the rootfs or one of its ancestors"
            }
            Self::BindSourceReachesStateRoot => {
                "bind mount source must not expose the container state store"
            }
            Self::BindSourcePseudoFs => {
                "bind mount source must not be on a pseudo filesystem such as procfs or sysfs"
            }
            Self::BindTargetKindMismatch => {
                "bind mount target kind does not match the source (directory vs regular file)"
            }
            Self::LandlockMountIdentityMismatch => {
                "the mount identity of a landlock rule target differs from the one recorded after mounting"
            }
            Self::LandlockMountNotRoot => "the landlock rule target is not the root of its mount",
            Self::LandlockMountNotReadOnly => {
                "the landlock rule target relies on a read-only mount but the mount is writable"
            }
            Self::HostDeviceNodeUnexpected => {
                "host device node is not the expected character device; refusing to bind it"
            }
            Self::RootfsIsHostRoot => "rootfs must not be the host root '/'",
            Self::RootfsOnSharedMount => {
                "rootfs is on a shared mount; isolate the mount namespace first"
            }
            Self::RootfsMoved => "rootfs was moved or removed after validation",
            Self::RootfsHasSubmounts => {
                "rootfs contains existing mounts; unknown submounts are not allowed"
            }
            Self::RootfsHasExternalHardlink => {
                "rootfs contains a file hard-linked to an inode outside the rootfs"
            }
            Self::EntrypointIsRuntimeBinary => {
                "the entrypoint is the runtime's own executable; refusing to exec it"
            }
            Self::EntrypointInterpreterIsRuntimeBinary => {
                "the interpreter of the entrypoint resolves to the runtime's own executable; \
                 refusing to exec it"
            }
            Self::ExecDevNotDirectory => "/dev in the new root is not a directory",
            Self::ExecProcNotProcfs => {
                "/proc in the new root is not procfs; cannot reopen a verified file"
            }
            Self::EntrypointCopyTooLarge => {
                "the entrypoint is too large to copy into a sealed executable copy; refusing to exec it"
            }
            Self::EntrypointCopySealUnverified => {
                "the seals of the entrypoint copy could not be verified; refusing to exec it"
            }
            Self::EntrypointOnNoexecMount => {
                "the entrypoint is on a noexec mount; refusing to exec it from a sealed copy"
            }
            Self::StdioNullNotNullDevice => {
                "/dev/null in the new root is not the null device (1:3); refusing to open it"
            }
            Self::ExecTargetNotNestedPid1 => {
                "the exec target is not PID 1 of a directly nested PID namespace"
            }
            Self::ExecTargetCgroupMismatch => {
                "the exec target does not belong to the recorded container cgroup"
            }
            Self::ExecTargetSharesPidNamespace => {
                "the exec target shares the PID namespace with the caller; refusing to join"
            }
            Self::ExecTargetSharesMountNamespace => {
                "the exec target shares the mount namespace with the caller; refusing to join"
            }
            Self::ExecTargetInOtherUserNamespace => {
                "the user namespace of the exec target or the caller changed since it was verified; refusing to join"
            }
            Self::ExecRootNotContainerRootfs => {
                "the root directory after joining is not the recorded container rootfs"
            }
            Self::ExecJoinedNamespaceMismatch => {
                "the user or mount namespace after joining is not the one of the prepared exec target"
            }
            Self::ExecJoinedPidNamespaceMismatch => {
                "the PID namespace after joining is not the one of the prepared exec target"
            }
            Self::ExecJoinedCgroupMismatch => {
                "the cgroup after joining is not the one of the prepared exec target"
            }
            Self::ExecTargetPidfdMismatch => {
                "the process held by the launch pidfd is not the recorded exec target"
            }
            Self::ReadonlyPathApplyFailed => "failed to apply a read-only path protection",
            Self::MaskedPathApplyFailed => "failed to apply a masked path protection",
            Self::SysfsApplyFailed => "failed to apply the read-only sysfs mount",
        }
    }
}

/// 違反記録の対象として保持する文字列の上限（文字数。超過分は切り詰める）。
pub const VIOLATION_SUBJECT_MAX_CHARS: usize = 256;

/// 違反の対象（呼び出し側が渡したパス。exec の対象の cgroup 不一致では、記録から導いた期待 cgroup パス）。Cc・Cf・Zl・Zp の文字とバックスラッシュはエスケープ済みで、
/// 長さは [`VIOLATION_SUBJECT_MAX_CHARS`] 文字以下（ログ注入・無制限確保を防ぐ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViolationSubject {
    text: String,
    truncated: bool,
}

impl ViolationSubject {
    /// パスから作る。非 UTF-8 のバイトは U+FFFD に置き換え、Unicode 一般カテゴリ Cc・Cf・Zl・Zp の文字（改行・ESC・双方向制御等。判定は `crate::sanitize`）と
    /// `\` は `char::escape_default` 形式でエスケープする。
    pub(super) fn from_path(path: &Path) -> Self {
        let lossy = path.to_string_lossy();
        let mut text = String::new();
        let mut count = 0usize;
        let mut truncated = false;
        for c in lossy.chars() {
            let escaped: String = if is_display_unsafe_char(c) || c == '\\' {
                c.escape_default().collect()
            } else {
                c.to_string()
            };
            let len = escaped.chars().count();
            if count + len > VIOLATION_SUBJECT_MAX_CHARS {
                truncated = true;
                break;
            }
            count += len;
            text.push_str(&escaped);
        }
        Self { text, truncated }
    }

    /// エスケープ・切り詰め済みの文字列。
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// 上限で切り詰めたか。
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// 分離違反の試行を拒否したときの構造化された記録（SEC-4 の記録経路。マウント層の写像は TASK-41.4、exec 対象の写像は #1465）。
///
/// `ExecError::violation` から取り出す。生成は `crate::exec` の拒否経路のみ。
///
/// - **記録の経路のみ**: ファイルへの永続化は `audit_log` に実装済みだが、本番経路への sink の
///   配線は未実装（REPAIR-3）。呼び出し側は受け取った記録を必要に応じて自分で扱う
/// - **違反**（構成・呼び出し文脈・パスが分離の前提を満たさず fail-closed で拒否したもの）
///   にだけ付く。**システムエラー**（syscall 失敗・procfs の読み取り失敗・mountinfo の書式
///   不正・権限不足）と hostname の書式エラーには付かない
/// - namespace の識別子や正規化後のホスト側実パスは含めない
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IsolationViolation {
    /// 種別。
    pub kind: ViolationKind,
    /// 理由コード。
    pub reason: ViolationReason,
    /// 違反した前提のビヘイビア ID（例: `"CORE-1"`・`"SEC-5"`）。
    pub behavior_id: &'static str,
    /// 対象（パスの検証で拒否した場合のみ）。
    pub subject: Option<ViolationSubject>,
    /// 監査レコード用の生パス（エスケープ・切り詰め前。`AuditPath` が 4096 バイトで切り詰める）。
    audit_path: Option<AuditPath>,
}

impl IsolationViolation {
    /// 理由から作る（種別・ビヘイビア ID は理由から決まる）。
    pub(super) fn new(reason: ViolationReason, subject: Option<&Path>) -> Self {
        Self {
            kind: reason.kind(),
            reason,
            behavior_id: reason.behavior_id(),
            subject: subject.map(ViolationSubject::from_path),
            audit_path: subject.map(AuditPath::new),
        }
    }

    /// 監査用の生パス（SEC-4・TASK-41.4）。エスケープは書き込み側（TASK-41.5 系）の責務で、
    /// `subject` のエスケープ済み文字列は流用しない（二重エスケープ・表記ずれを避ける）。
    pub fn audit_path(&self) -> Option<&AuditPath> {
        self.audit_path.as_ref()
    }

    /// exec の対象の違反（種別 `ExecTarget`）なら `ExecTarget` 監査イベントを返す（SEC-4・SUP-6・#1465）。
    ///
    /// 理由コードだけを載せ、`audit_path`（期待 cgroup パス等）は使わない。
    pub fn exec_audit_event(&self) -> Option<AuditEvent> {
        self.reason.exec_target_audit_event()
    }

    /// エントリポイント検証の違反（種別 `Entrypoint`）なら `Entrypoint` 監査イベントを返す（SEC-4・SUP-6・#1595）。
    ///
    /// 理由コードだけを載せ、`audit_path` は使わない。
    pub fn entrypoint_audit_event(&self) -> Option<AuditEvent> {
        self.reason.entrypoint_audit_event()
    }

    /// マウント検証層の違反なら `Mount` 監査イベントを返す（SEC-4・TASK-41.4）。
    ///
    /// 対象は `MountTarget`・`SharedPropagation`・`RootfsPivot`・`ProtectedPathApply`。計画・establish 前提・証跡不一致・
    /// エントリポイントはマウント層の拒否ではないため `None`（エントリポイントは [`Self::entrypoint_audit_event`]、
    /// exec の対象の拒否は [`Self::exec_audit_event`] が記録する）。
    pub fn mount_audit_event(&self) -> Option<AuditEvent> {
        self.reason.mount_layer_audit_event(self.audit_path.clone())
    }
}

/// [`ViolationReason::from_landlock_apply_kind`] の自由関数版（`exec/landlock.rs` が呼ぶ入口）。
///
/// worker の経路のソース走査（`violation_scan`）は `ViolationReason::<名前>` の字面を数えるため、launch 経路でだけ
/// 生じる本理由の引き直しは自由関数を経由する（exec の再適用は `NotRecorded` でこの違反を作らない。#2071）。
pub(super) fn landlock_apply_violation(
    kind: &crate::landlock::LandlockApplyErrorKind,
) -> Option<ViolationReason> {
    ViolationReason::from_landlock_apply_kind(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-4・CORE-5・#2130: Landlock 段の 3 理由の一覧は `from_landlock_apply_kind` の分岐と一致し、トークンから
    /// 引き直せる。種別は `MountTarget` で、他の種別・未知のトークンは引き直さない。
    #[test]
    fn sec4_2130_landlock_apply_reasons_match_kind_mapping() {
        use crate::landlock::LandlockApplyErrorKind as K;
        let kinds = [
            K::MountIdentityMismatch { index: 0 },
            K::MountNotRoot { index: 0 },
            K::MountNotReadOnly { index: 0 },
        ];
        let mapped: Vec<ViolationReason> = kinds
            .iter()
            .filter_map(ViolationReason::from_landlock_apply_kind)
            .collect();
        assert_eq!(mapped, ViolationReason::LANDLOCK_APPLY_REASONS.to_vec());
        for r in ViolationReason::LANDLOCK_APPLY_REASONS {
            assert_eq!(r.kind(), ViolationKind::MountTarget);
            assert_eq!(
                ViolationReason::from_landlock_apply_token(r.as_str()),
                Some(r)
            );
        }
        assert_eq!(
            ViolationReason::from_landlock_apply_token("no_namespaces"),
            None
        );
        assert_eq!(
            ViolationReason::from_landlock_apply_token("entrypoint_is_runtime_binary"),
            None
        );
        assert_eq!(ViolationReason::from_landlock_apply_token(""), None);
    }

    /// SEC-4・#2130: 計画の拒否(`PlanRejected`)だけが launch 専用の写像で `Mount`(パスなし・理由つき)になる。
    /// 共有の写像(`launch_mount_audit_event` の `plan_rejected` の扱い)は変わらない(#2109 の判断)。
    #[test]
    fn sec4_2130_launch_plan_audit_event_maps_only_plan_rejected() {
        for r in ViolationReason::ALL {
            let ev = r.launch_plan_audit_event();
            if r.kind() == ViolationKind::PlanRejected {
                assert_eq!(
                    ev,
                    Some(AuditEvent::Mount {
                        path: None,
                        reason: Some(AuditReason::new(r.as_str())),
                    }),
                    "{r:?}"
                );
            } else {
                assert_eq!(ev, None, "{r:?}");
            }
        }
        assert_eq!(
            ViolationReason::NoNamespaces.mount_layer_audit_event(None),
            None
        );
    }

    /// `ALL` は `as_str` の全分岐を網羅する（足し忘れの検出。SEC-4・#1815）。
    #[test]
    fn sec4_1815_all_reasons_covers_every_variant() {
        let src = include_str!("violation.rs");
        let start = src
            .find("/// 機械可読な理由コード（snake_case）。")
            .unwrap();
        let end = src.find("/// 違反の種別。\n    pub fn kind").unwrap();
        let arms = src[start..end]
            .lines()
            .filter(|l| l.contains("Self::") && l.contains("=>"))
            .count();
        assert_eq!(ViolationReason::ALL.len(), arms);
        let mut names: Vec<&str> = ViolationReason::ALL.iter().map(|r| r.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), arms);
    }

    /// SEC-4・SEC-2・#2013: 読み取り専用化・覆いの適用失敗の 2 理由は、トークン・種別・ビヘイビア ID・段・
    /// `ErrorCode`・`Mount` 監査イベントが具体値で決まる。`from_launch_token` は通さない（段つきの許可リストが担う）。
    #[test]
    fn sec4_2013_protected_path_apply_reasons_have_fixed_values() {
        let table = [
            (
                ViolationReason::ReadonlyPathApplyFailed,
                "readonly_path_apply_failed",
                IsolationStage::MountReadonlyPaths,
                "failed to apply a read-only path protection",
            ),
            (
                ViolationReason::MaskedPathApplyFailed,
                "masked_path_apply_failed",
                IsolationStage::MountMaskedPaths,
                "failed to apply a masked path protection",
            ),
            (
                ViolationReason::SysfsApplyFailed,
                "sysfs_apply_failed",
                IsolationStage::MountSysfs,
                "failed to apply the read-only sysfs mount",
            ),
        ];
        assert_eq!(ViolationReason::PROTECTED_PATH_APPLY_REASONS.len(), 3);
        for (r, token, stage, msg) in table {
            assert!(ViolationReason::PROTECTED_PATH_APPLY_REASONS.contains(&r));
            assert_eq!(r.as_str(), token);
            assert_eq!(r.kind(), ViolationKind::ProtectedPathApply);
            assert_eq!(r.kind().as_str(), "protected_path_apply");
            assert_eq!(r.behavior_id(), "SEC-2");
            assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
            assert_eq!(r.stage(), stage);
            assert_eq!(r.message(), msg);
            assert_eq!(ViolationReason::from_launch_token(token), None);
            assert_eq!(
                r.launch_mount_audit_event(),
                Some(AuditEvent::Mount {
                    path: None,
                    reason: Some(AuditReason::new(token)),
                })
            );
            // worker の経路には載らない（二重記録なし）。
            assert_eq!(r.exec_worker_audit_event(), None);
        }
    }

    /// 引き直しは pivot 前段の 5 種別だけを受け付ける（SEC-4・#1815）。
    #[test]
    fn sec4_1815_launch_token_accepts_only_prepivot_kinds() {
        for r in ViolationReason::ALL {
            let accepted = match r.kind() {
                ViolationKind::MountTarget
                | ViolationKind::SharedPropagation
                | ViolationKind::RootfsPivot
                | ViolationKind::EstablishPrecondition
                | ViolationKind::EvidenceMismatch => true,
                ViolationKind::PlanRejected
                | ViolationKind::Entrypoint
                | ViolationKind::ExecTarget
                | ViolationKind::ProtectedPathApply => false,
            };
            let expected = accepted.then_some(r);
            assert_eq!(ViolationReason::from_launch_token(r.as_str()), expected);
        }
        assert_eq!(
            ViolationReason::from_launch_token("target_on_shared_mount"),
            Some(ViolationReason::TargetOnSharedMount)
        );
        assert_eq!(ViolationReason::from_launch_token("plan_rejected"), None);
        assert_eq!(ViolationReason::from_launch_token(""), None);
    }

    /// bind mount の段の user namespace 由来 2 理由が `Mount` 監査イベントに写り、パスは載らない（SEC-4・#2072）。
    #[test]
    fn sec4_2072_launch_mount_audit_event_maps_user_namespace_reasons() {
        for r in ViolationReason::MOUNT_BINDS_USER_NAMESPACE_REASONS {
            assert_eq!(ViolationReason::from_launch_token(r.as_str()), None);
            assert_eq!(
                r.launch_mount_audit_event(),
                Some(AuditEvent::Mount {
                    path: None,
                    reason: Some(AuditReason::new(r.as_str())),
                })
            );
            // 共有の写像は広げていない（plan() 時点の拒否の記録は変わらない）。
            assert_eq!(r.mount_layer_audit_event(None), None);
        }
        assert_eq!(
            ViolationReason::NoNamespaces.launch_mount_audit_event(),
            None
        );
    }

    /// 監査イベントはマウント層の 3 種別だけに写り、パスは載らない（SEC-4・#1815）。
    #[test]
    fn sec4_1815_launch_mount_audit_event_maps_mount_layer_only() {
        assert_eq!(
            ViolationReason::PathMissing.launch_mount_audit_event(),
            Some(AuditEvent::Mount {
                path: None,
                reason: Some(AuditReason::new("path_missing")),
            })
        );
        assert_eq!(
            ViolationReason::RootfsIsHostRoot.launch_mount_audit_event(),
            Some(AuditEvent::Mount {
                path: None,
                reason: Some(AuditReason::new("rootfs_is_host_root")),
            })
        );
        assert_eq!(
            ViolationReason::EstablishNotPid1.launch_mount_audit_event(),
            None
        );
        assert_eq!(
            ViolationReason::EvidenceCallerNotPid1.launch_mount_audit_event(),
            None
        );
    }

    /// 制御文字・バックスラッシュはエスケープし、通常の文字はそのまま保持する。
    #[test]
    fn subject_escapes_control_chars() {
        let s = ViolationSubject::from_path(Path::new("/a\nb\u{1b}[31m\\c/日本"));
        assert_eq!(s.as_str(), "/a\\nb\\u{1b}[31m\\\\c/日本");
        assert!(!s.is_truncated());
    }

    /// SEC-4: Cf（双方向制御・WORD JOINER）と Zl・Zp も `escape_default` 形式でエスケープする。
    #[test]
    fn sec4_subject_escapes_format_and_separator_chars() {
        let s = ViolationSubject::from_path(Path::new("/a\u{202E}b\u{2060}c\u{2028}d\u{2029}e"));
        assert_eq!(s.as_str(), "/a\\u{202e}b\\u{2060}c\\u{2028}d\\u{2029}e");
        assert!(!s.is_truncated());
    }

    /// SEC-4: Cf のエスケープ列（8 文字）でも上限 256 文字を超えず、途中で切らない。
    #[test]
    fn sec4_subject_bound_holds_with_format_char_escapes() {
        // 1 個 8 文字のエスケープ列が 32 個でちょうど 256 文字（33 個目で切り詰め）。
        let many = "\u{202E}".repeat(33);
        let s = ViolationSubject::from_path(Path::new(&many));
        assert_eq!(s.as_str().chars().count(), 256);
        assert!(s.is_truncated());
        let fit = format!("/{}\u{202E}", "a".repeat(247));
        let s = ViolationSubject::from_path(Path::new(&fit));
        assert_eq!(s.as_str().chars().count(), 256);
        assert!(!s.is_truncated());
        let over = format!("/{}\u{202E}", "a".repeat(248));
        let s = ViolationSubject::from_path(Path::new(&over));
        assert_eq!(s.as_str().chars().count(), 249);
        assert!(s.is_truncated());
    }

    /// 上限を超えるパスは上限の文字数で切り詰め、切り詰めたことを記録する。
    #[test]
    fn subject_is_bounded() {
        let long = format!("/{}", "a".repeat(1000));
        let s = ViolationSubject::from_path(Path::new(&long));
        assert_eq!(s.as_str().chars().count(), VIOLATION_SUBJECT_MAX_CHARS);
        assert!(s.is_truncated());
        // エスケープ列の途中では切らない（上限 256 に対して "\n" 1 個は 2 文字）。
        let edge = format!("/{}\n", "a".repeat(VIOLATION_SUBJECT_MAX_CHARS - 2));
        let s = ViolationSubject::from_path(Path::new(&edge));
        assert_eq!(s.as_str().chars().count(), VIOLATION_SUBJECT_MAX_CHARS - 1);
        assert!(s.is_truncated());
    }

    /// 理由コード・種別・ビヘイビア ID の具体値。
    #[test]
    fn reason_metadata_is_exact() {
        let r = ViolationReason::HostRootIdentityMapping;
        assert_eq!(r.as_str(), "host_root_identity_mapping");
        assert_eq!(r.kind(), ViolationKind::PlanRejected);
        assert_eq!(r.behavior_id(), "SEC-5");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        let r = ViolationReason::TargetOnSharedMount;
        assert_eq!(r.kind().as_str(), "shared_propagation");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.stage(), IsolationStage::MountProc);
    }

    /// CORE-1（TASK-27.3）: rootfs 切替の理由コード・種別・`ErrorCode`・段の具体値。
    #[test]
    fn core1_rootfs_reason_metadata_is_exact() {
        let r = ViolationReason::RootfsIsHostRoot;
        assert_eq!(r.as_str(), "rootfs_is_host_root");
        assert_eq!(r.kind().as_str(), "rootfs_pivot");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.error_code(), ErrorCode::InvalidArgument);
        assert_eq!(r.stage(), IsolationStage::PrepareRootfs);
        assert_eq!(r.message(), "rootfs must not be the host root '/'");
        let r = ViolationReason::RootfsOnSharedMount;
        assert_eq!(r.as_str(), "rootfs_on_shared_mount");
        assert_eq!(r.kind().as_str(), "shared_propagation");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        let r = ViolationReason::RootfsMoved;
        assert_eq!(r.as_str(), "rootfs_moved");
        assert_eq!(r.kind().as_str(), "rootfs_pivot");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        let r = ViolationReason::RootfsHasSubmounts;
        assert_eq!(r.as_str(), "rootfs_has_submounts");
        assert_eq!(r.kind().as_str(), "rootfs_pivot");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        assert_eq!(r.stage(), IsolationStage::PrepareRootfs);
        let r = ViolationReason::RootfsHasExternalHardlink;
        assert_eq!(r.as_str(), "rootfs_has_external_hardlink");
        assert_eq!(r.kind().as_str(), "rootfs_pivot");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        assert_eq!(r.stage(), IsolationStage::PrepareRootfs);
    }

    /// CORE-1（TASK-27.4.1）: エントリポイント検証の理由コード・種別・`ErrorCode`・段の具体値。
    #[test]
    fn core1_entrypoint_reason_metadata_is_exact() {
        let r = ViolationReason::EntrypointIsRuntimeBinary;
        assert_eq!(r.as_str(), "entrypoint_is_runtime_binary");
        assert_eq!(r.kind().as_str(), "entrypoint");
        assert_eq!(r.behavior_id(), "CORE-1");
        assert_eq!(r.error_code(), ErrorCode::PermissionDenied);
        assert_eq!(r.stage(), IsolationStage::Exec);
    }

    /// SUP-6・SEC-1・SEC-4（TASK-163 追補・#1458）: インタープリタ経由の拒否の理由コード・種別・ビヘイビア ID・
    /// `ErrorCode`・段・メッセージの具体値。
    #[test]
    fn sec4_sup6_task163_interpreter_reason_metadata_is_exact() {
        let r = ViolationReason::EntrypointInterpreterIsRuntimeBinary;
        assert_eq!(r.as_str(), "entrypoint_interpreter_is_runtime_binary");
        assert_eq!(r.kind().as_str(), "entrypoint");
        assert_eq!(r.behavior_id(), "SEC-1");
        assert_eq!(r.error_code(), ErrorCode::PermissionDenied);
        assert_eq!(r.stage(), IsolationStage::Exec);
        assert_eq!(
            r.message(),
            "the interpreter of the entrypoint resolves to the runtime's own executable; \
             refusing to exec it"
        );
        let v = IsolationViolation::new(r, Some(Path::new("/script")));
        assert_eq!(v.mount_audit_event(), None);
    }

    /// SUP-6・SEC-1・SEC-4（TASK-163 追補・#1531）: 封印した複製の拒否理由の具体値。
    #[test]
    fn sec4_sup6_task163_sealed_copy_reason_metadata_is_exact() {
        for (r, code, error_code, message) in [
            (
                ViolationReason::EntrypointCopyTooLarge,
                "entrypoint_copy_too_large",
                ErrorCode::PermissionDenied,
                "the entrypoint is too large to copy into a sealed executable copy; refusing to exec it",
            ),
            (
                ViolationReason::EntrypointCopySealUnverified,
                "entrypoint_copy_seal_unverified",
                ErrorCode::FailedPrecondition,
                "the seals of the entrypoint copy could not be verified; refusing to exec it",
            ),
            (
                ViolationReason::EntrypointOnNoexecMount,
                "entrypoint_on_noexec_mount",
                ErrorCode::PermissionDenied,
                "the entrypoint is on a noexec mount; refusing to exec it from a sealed copy",
            ),
        ] {
            assert_eq!(r.as_str(), code);
            assert_eq!(r.kind().as_str(), "entrypoint");
            assert_eq!(r.behavior_id(), "SEC-1");
            assert_eq!(r.error_code(), error_code);
            assert_eq!(r.stage(), IsolationStage::Exec);
            assert_eq!(r.message(), message);
        }
    }

    /// SUP-6・SEC-1・SEC-4（TASK-163 追補・#1459）: `/dev`・`/proc` の差し替えの理由コード・種別・ビヘイビア ID・
    /// `ErrorCode`・段・メッセージの具体値。
    #[test]
    fn sec4_sup6_task163_dev_and_proc_reason_metadata_is_exact() {
        for (r, code, message) in [
            (
                ViolationReason::ExecDevNotDirectory,
                "exec_dev_not_directory",
                "/dev in the new root is not a directory",
            ),
            (
                ViolationReason::ExecProcNotProcfs,
                "exec_proc_not_procfs",
                "/proc in the new root is not procfs; cannot reopen a verified file",
            ),
        ] {
            assert_eq!(r.as_str(), code);
            assert_eq!(r.kind().as_str(), "entrypoint");
            assert_eq!(r.behavior_id(), "SEC-1");
            assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
            assert_eq!(r.stage(), IsolationStage::Exec);
            assert_eq!(r.message(), message);
            assert_eq!(IsolationViolation::new(r, None).mount_audit_event(), None);
        }
    }

    /// SUP-6・SEC-1・SEC-4（TASK-163 追補・#1459）: `/dev/null` 差し替えの理由コード・種別・ビヘイビア ID・
    /// `ErrorCode`・段・メッセージの具体値。マウント層の違反ではないため `Mount` 監査イベントへは写らない。
    #[test]
    fn sec4_sup6_task163_stdio_null_reason_metadata_is_exact() {
        let r = ViolationReason::StdioNullNotNullDevice;
        assert_eq!(r.as_str(), "stdio_null_not_null_device");
        assert_eq!(r.kind().as_str(), "entrypoint");
        assert_eq!(r.behavior_id(), "SEC-1");
        assert_eq!(r.error_code(), ErrorCode::PermissionDenied);
        assert_eq!(r.stage(), IsolationStage::Exec);
        assert_eq!(
            r.message(),
            "/dev/null in the new root is not the null device (1:3); refusing to open it"
        );
        let v = IsolationViolation::new(r, Some(Path::new("/dev/null")));
        assert_eq!(v.mount_audit_event(), None);
    }

    /// SEC-4・SEC-1・SUP-6（TASK-163.1）: exec の対象の検証の理由コード・種別・ビヘイビア ID・`ErrorCode`・
    /// 段・メッセージの具体値。マウント層の違反ではないため `Mount` 監査イベントへは写らない。
    #[test]
    fn sec4_sup6_exec_target_reason_metadata_is_exact() {
        let cases = [
            (
                ViolationReason::ExecTargetNotNestedPid1,
                "exec_target_not_nested_pid1",
                "SUP-6",
                "the exec target is not PID 1 of a directly nested PID namespace",
            ),
            (
                ViolationReason::ExecTargetCgroupMismatch,
                "exec_target_cgroup_mismatch",
                "SEC-1",
                "the exec target does not belong to the recorded container cgroup",
            ),
            (
                ViolationReason::ExecTargetSharesPidNamespace,
                "exec_target_shares_pid_namespace",
                "SUP-6",
                "the exec target shares the PID namespace with the caller; refusing to join",
            ),
            (
                ViolationReason::ExecTargetSharesMountNamespace,
                "exec_target_shares_mount_namespace",
                "SUP-6",
                "the exec target shares the mount namespace with the caller; refusing to join",
            ),
            (
                ViolationReason::ExecTargetInOtherUserNamespace,
                "exec_target_in_other_user_namespace",
                "SUP-6",
                "the user namespace of the exec target or the caller changed since it was verified; refusing to join",
            ),
            (
                ViolationReason::ExecRootNotContainerRootfs,
                "exec_root_not_container_rootfs",
                "SEC-1",
                "the root directory after joining is not the recorded container rootfs",
            ),
            (
                ViolationReason::ExecJoinedNamespaceMismatch,
                "exec_joined_namespace_mismatch",
                "SEC-1",
                "the user or mount namespace after joining is not the one of the prepared exec target",
            ),
            (
                ViolationReason::ExecJoinedPidNamespaceMismatch,
                "exec_joined_pid_namespace_mismatch",
                "SEC-1",
                "the PID namespace after joining is not the one of the prepared exec target",
            ),
            (
                ViolationReason::ExecJoinedCgroupMismatch,
                "exec_joined_cgroup_mismatch",
                "SEC-1",
                "the cgroup after joining is not the one of the prepared exec target",
            ),
            (
                ViolationReason::ExecTargetPidfdMismatch,
                "exec_target_pidfd_mismatch",
                "SUP-6",
                "the process held by the launch pidfd is not the recorded exec target",
            ),
        ];
        for (r, code, behavior, message) in cases {
            assert_eq!(r.as_str(), code);
            assert_eq!(r.kind(), ViolationKind::ExecTarget);
            assert_eq!(r.kind().as_str(), "exec_target");
            assert_eq!(r.behavior_id(), behavior);
            assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
            assert_eq!(r.stage(), IsolationStage::SetNs);
            assert_eq!(r.message(), message);
            let v = IsolationViolation::new(r, None);
            assert_eq!(v.mount_audit_event(), None);
        }
    }

    /// SEC-4・TASK-41.4: 理由ごとの Mount 写像の有無を具体値で照合し、生パスを保持する。
    #[test]
    fn sec4_task41_4_mount_audit_event_mapping() {
        let mapped = [
            (ViolationReason::PathParentComponent, true),
            (ViolationReason::TargetOutsideRootfs, true),
            (ViolationReason::TargetOnSharedMount, true),
            (ViolationReason::RootfsIsHostRoot, true),
            (ViolationReason::RootfsHasExternalHardlink, true),
            (ViolationReason::NoNamespaces, false),
            (ViolationReason::EstablishNotPid1, false),
            (ViolationReason::EvidenceCallerNotPid1, false),
            (ViolationReason::EntrypointIsRuntimeBinary, false),
        ];
        for (reason, expect) in mapped {
            let v = IsolationViolation::new(reason, Some(Path::new("/x")));
            assert_eq!(v.mount_audit_event().is_some(), expect, "{reason:?}");
        }
        let raw = Path::new("/a\nb\\c");
        let v = IsolationViolation::new(ViolationReason::PathParentComponent, Some(raw));
        assert_eq!(v.audit_path().map(|p| p.as_path()), Some(raw));
        let v = IsolationViolation::new(ViolationReason::RootfsMissing, None);
        assert_eq!(
            v.mount_audit_event(),
            Some(AuditEvent::Mount {
                path: None,
                reason: Some(AuditReason::new("rootfs_missing")),
            })
        );
    }

    /// SEC-4・TASK-41.4 追補（#1701）: マウント層に写る全 17 理由が、パスあり・なしのどちらでも
    /// 理由コード（静的トークンの具体値）つきの `Mount` になる。他の種別は `None` のまま。
    #[test]
    fn sec4_task41_4_1701_mount_audit_event_carries_reason_token() {
        use ViolationKind::{MountTarget, RootfsPivot, SharedPropagation};
        let table = [
            (
                ViolationReason::PathNotAbsolute,
                "path_not_absolute",
                MountTarget,
            ),
            (
                ViolationReason::PathContainsNul,
                "path_contains_nul",
                MountTarget,
            ),
            (
                ViolationReason::PathParentComponent,
                "path_parent_component",
                MountTarget,
            ),
            (
                ViolationReason::TargetOutsideRootfs,
                "target_outside_rootfs",
                MountTarget,
            ),
            (
                ViolationReason::RootfsMissing,
                "rootfs_missing",
                MountTarget,
            ),
            (
                ViolationReason::RootfsSymlinkOrNotDirectory,
                "rootfs_symlink_or_not_directory",
                MountTarget,
            ),
            (
                ViolationReason::TargetIsRootfs,
                "target_is_rootfs",
                MountTarget,
            ),
            (
                ViolationReason::PathSymlinkOrNotDirectory,
                "path_symlink_or_not_directory",
                MountTarget,
            ),
            (ViolationReason::PathMissing, "path_missing", MountTarget),
            (ViolationReason::TargetMoved, "target_moved", MountTarget),
            (
                ViolationReason::HostDeviceNodeUnexpected,
                "host_device_node_unexpected",
                MountTarget,
            ),
            (
                ViolationReason::TargetOnSharedMount,
                "target_on_shared_mount",
                SharedPropagation,
            ),
            (
                ViolationReason::RootfsOnSharedMount,
                "rootfs_on_shared_mount",
                SharedPropagation,
            ),
            (
                ViolationReason::RootfsIsHostRoot,
                "rootfs_is_host_root",
                RootfsPivot,
            ),
            (ViolationReason::RootfsMoved, "rootfs_moved", RootfsPivot),
            (
                ViolationReason::RootfsHasSubmounts,
                "rootfs_has_submounts",
                RootfsPivot,
            ),
            (
                ViolationReason::RootfsHasExternalHardlink,
                "rootfs_has_external_hardlink",
                RootfsPivot,
            ),
        ];
        assert_eq!(table.len(), 17);
        for (reason, token, kind) in table {
            assert_eq!(reason.kind(), kind, "{reason:?}");
            assert_eq!(reason.as_str(), token, "{reason:?}");
            let with_path = IsolationViolation::new(reason, Some(Path::new("/x")));
            assert_eq!(
                with_path.mount_audit_event(),
                Some(AuditEvent::Mount {
                    path: Some(AuditPath::new(Path::new("/x"))),
                    reason: Some(AuditReason::new(token)),
                }),
                "{reason:?}"
            );
            let no_path = IsolationViolation::new(reason, None);
            assert_eq!(
                no_path.mount_audit_event(),
                Some(AuditEvent::Mount {
                    path: None,
                    reason: Some(AuditReason::new(token)),
                }),
                "{reason:?}"
            );
        }
        for reason in [
            ViolationReason::NoNamespaces,
            ViolationReason::EstablishNotPid1,
            ViolationReason::EvidenceCallerNotPid1,
            ViolationReason::EntrypointIsRuntimeBinary,
        ] {
            let v = IsolationViolation::new(reason, Some(Path::new("/x")));
            assert_eq!(v.mount_audit_event(), None, "{reason:?}");
        }
    }

    /// CORE-6・SEC-5・SEC-4（TASK-29 追補・#1660）: ホストのデバイスノードの不一致の理由コード・種別・ビヘイビア ID・
    /// `ErrorCode`・メッセージの具体値と、層 Mount へのパス付きの写像。
    #[test]
    fn core6_sec5_1660_host_device_node_unexpected_metadata_is_exact() {
        let r = ViolationReason::HostDeviceNodeUnexpected;
        assert_eq!(r.as_str(), "host_device_node_unexpected");
        assert_eq!(r.kind().as_str(), "mount_target");
        assert_eq!(r.behavior_id(), "SEC-5");
        assert_eq!(r.error_code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            r.message(),
            "host device node is not the expected character device; refusing to bind it"
        );
        let v = IsolationViolation::new(r, Some(Path::new("/dev/null")));
        assert_eq!(
            v.mount_audit_event(),
            Some(AuditEvent::Mount {
                path: Some(AuditPath::new(Path::new("/dev/null"))),
                reason: Some(AuditReason::new("host_device_node_unexpected")),
            })
        );
        assert_eq!(v.exec_audit_event(), None);
    }

    /// SEC-4・SUP-6・TASK-163 追補: exec 対象の 10 理由は許可リスト往復でき、対象外・未知は引けない。
    #[test]
    fn sec4_sup6_task163_exec_target_token_allowlist() {
        assert_eq!(ViolationReason::EXEC_TARGET_REASONS.len(), 10);
        for r in ViolationReason::EXEC_TARGET_REASONS {
            assert_eq!(r.kind(), ViolationKind::ExecTarget);
            assert_eq!(ViolationReason::from_exec_target_token(r.as_str()), Some(r));
        }
        for t in [
            "target_moved",
            "entrypoint_is_runtime_binary",
            "",
            "unknown",
            "exec_target",
        ] {
            assert_eq!(ViolationReason::from_exec_target_token(t), None, "{t}");
        }
        assert_eq!(
            ViolationReason::EntrypointIsRuntimeBinary.exec_target_audit_event(),
            None
        );
    }

    /// SEC-4・SUP-6・SEC-1: worker の経路の 14 理由は `<種別>/<理由>` で往復でき、層は exec_target か mount の
    /// どちらか 1 つだけ（パスなし）。一覧外・種別の食い違い・未知は引けず、監査イベントも作らない。
    #[test]
    fn sec4_sup6_exec_worker_token_allowlist_maps_each_reason_to_one_layer() {
        assert_eq!(ViolationReason::EXEC_WORKER_REASONS.len(), 14);
        for r in ViolationReason::EXEC_TARGET_REASONS {
            assert!(ViolationReason::EXEC_WORKER_REASONS.contains(&r), "{r:?}");
        }
        for r in ViolationReason::EXEC_WORKER_REASONS {
            assert_eq!(
                ViolationReason::from_exec_worker_token(r.kind().as_str(), r.as_str()),
                Some(r)
            );
            let expected = match r.kind() {
                ViolationKind::ExecTarget => AuditEvent::ExecTarget {
                    reason: AuditReason::new(r.as_str()),
                },
                ViolationKind::RootfsPivot | ViolationKind::MountTarget => AuditEvent::Mount {
                    path: None,
                    reason: Some(AuditReason::new(r.as_str())),
                },
                other => panic!("unexpected worker violation kind {other:?}"),
            };
            assert_eq!(r.exec_worker_audit_event(), Some(expected), "{r:?}");
            // 二重記録なし: entrypoint 層には写らない。
            assert_eq!(r.entrypoint_audit_event(), None, "{r:?}");
        }
        assert_eq!(
            ViolationReason::RootfsIsHostRoot.exec_target_audit_event(),
            None
        );
        for (kind, reason) in [
            // 種別の食い違い。
            ("exec_target", "rootfs_is_host_root"),
            ("rootfs_pivot", "exec_target_not_nested_pid1"),
            // 同じ種別だが worker の経路では生じない理由（一覧外）。
            ("rootfs_pivot", "rootfs_moved"),
            ("rootfs_pivot", "rootfs_has_submounts"),
            ("mount_target", "target_moved"),
            ("entrypoint", "entrypoint_is_runtime_binary"),
            ("exec_target", "bogus"),
            ("", ""),
        ] {
            assert_eq!(
                ViolationReason::from_exec_worker_token(kind, reason),
                None,
                "{kind}/{reason}"
            );
        }
        for r in [
            ViolationReason::RootfsMoved,
            ViolationReason::TargetMoved,
            ViolationReason::EntrypointIsRuntimeBinary,
        ] {
            assert_eq!(r.exec_worker_audit_event(), None, "{r:?}");
        }
    }

    /// SEC-4・SUP-6・TASK-163 追補: 期待 cgroup パスを subject に持つ違反でもレコードにパスは載らない。
    #[test]
    fn sec4_sup6_task163_exec_audit_event_has_no_path() {
        let v = IsolationViolation::new(
            ViolationReason::ExecTargetCgroupMismatch,
            Some(Path::new("/sys/fs/cgroup/fandhe/c1")),
        );
        assert!(v.audit_path().is_some());
        let ev = v.exec_audit_event();
        assert_eq!(
            ev,
            Some(AuditEvent::ExecTarget {
                reason: AuditReason::new("exec_target_cgroup_mismatch")
            })
        );
        assert_eq!(v.mount_audit_event(), None);
    }

    /// SEC-4・SUP-6・TASK-163 追補・#1595: エントリポイントの 8 理由は許可リスト往復でき、対象外・未知は引けない。
    #[test]
    fn sec4_sup6_task163_entrypoint_token_allowlist() {
        assert_eq!(ViolationReason::ENTRYPOINT_REASONS.len(), 8);
        for r in ViolationReason::ENTRYPOINT_REASONS {
            assert_eq!(r.kind(), ViolationKind::Entrypoint);
            assert_eq!(ViolationReason::from_entrypoint_token(r.as_str()), Some(r));
        }
        for t in [
            "target_moved",
            "exec_target_cgroup_mismatch",
            "",
            "unknown",
            "entrypoint",
        ] {
            assert_eq!(ViolationReason::from_entrypoint_token(t), None, "{t}");
        }
        assert_eq!(
            ViolationReason::ExecTargetCgroupMismatch.entrypoint_audit_event(),
            None
        );
        assert_eq!(ViolationReason::TargetMoved.entrypoint_audit_event(), None);
    }

    /// SEC-4・SUP-6・TASK-163 追補・#1595: subject 付きでもレコードにパスは載らず、他層の写像は None（二重記録なし）。
    #[test]
    fn sec4_sup6_task163_entrypoint_audit_event_has_no_path() {
        let v = IsolationViolation::new(
            ViolationReason::EntrypointIsRuntimeBinary,
            Some(Path::new("/usr/bin/fandhe")),
        );
        assert!(v.audit_path().is_some());
        assert_eq!(
            v.entrypoint_audit_event(),
            Some(AuditEvent::Entrypoint {
                reason: AuditReason::new("entrypoint_is_runtime_binary")
            })
        );
        assert_eq!(v.mount_audit_event(), None);
        assert_eq!(v.exec_audit_event(), None);
    }

    /// SEC-4・SUP-6・TASK-163 追補・#1595: 8 理由それぞれで 1 件・層 entrypoint・パス無しで記録し、失敗でも error は不変。
    #[test]
    fn sec4_sup6_task163_record_entrypoint_rejection_records_once() {
        use crate::audit_log::mount::tests::VecSink;
        use crate::audit_log::{AuditDelivery, AuditLayer};
        use crate::exec::record_entrypoint_rejection;

        for r in ViolationReason::ENTRYPOINT_REASONS {
            let sink = VecSink::new(false);
            let out = record_entrypoint_rejection("rejected", r, None, &sink);
            assert_eq!(out.delivery, AuditDelivery::Recorded, "{r:?}");
            assert_eq!(out.error, "rejected");
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1, "{r:?}");
            assert_eq!(recs[0].layer(), AuditLayer::Entrypoint);
            assert_eq!(recs[0].reason().map(AuditReason::as_str), Some(r.as_str()));
            assert_eq!(recs[0].path(), None);
            assert_eq!(recs[0].pid().get(), std::process::id());

            let failing = VecSink::new(true);
            let out = record_entrypoint_rejection("rejected", r, None, &failing);
            assert!(
                matches!(out.delivery, AuditDelivery::SinkFailed(_)),
                "{r:?}"
            );
            assert_eq!(out.error, "rejected");
        }
        for r in [
            ViolationReason::ExecTargetCgroupMismatch,
            ViolationReason::TargetMoved,
        ] {
            let sink = VecSink::new(false);
            let out = record_entrypoint_rejection("x", r, None, &sink);
            assert_eq!(out.delivery, AuditDelivery::NotApplicable);
            assert_eq!(sink.snapshot().len(), 0);
        }
    }

    /// SEC-4・SUP-6・SEC-1: worker の経路の 14 理由はそれぞれ 1 件だけ記録される（exec 対象は層 exec_target と理由
    /// コード、`rootfs_is_host_root` と rootfs の固定の 2 理由〔#1702〕は層 mount で理由コードつき。どちらもパスなし）。一覧外は 0 件、失敗でも error は不変。
    #[test]
    fn sec4_sup6_record_exec_worker_rejection_records_once_per_reason() {
        use crate::audit_log::mount::tests::VecSink;
        use crate::audit_log::{AuditDelivery, AuditLayer};
        use crate::exec::record_exec_worker_rejection;

        for r in ViolationReason::EXEC_WORKER_REASONS {
            let sink = VecSink::new(false);
            let out = record_exec_worker_rejection("rejected", r, None, &sink);
            assert_eq!(out.delivery, AuditDelivery::Recorded, "{r:?}");
            assert_eq!(out.error, "rejected");
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1, "{r:?}");
            let layer = match r.kind() {
                ViolationKind::ExecTarget => AuditLayer::ExecTarget,
                _ => AuditLayer::Mount,
            };
            assert_eq!(recs[0].layer(), layer, "{r:?}");
            assert_eq!(recs[0].reason().map(AuditReason::as_str), Some(r.as_str()));
            assert_eq!(recs[0].path(), None);
            assert_eq!(recs[0].pid().get(), std::process::id());
            assert_eq!(recs[0].container_id(), None);

            let failing = VecSink::new(true);
            let out = record_exec_worker_rejection("rejected", r, None, &failing);
            assert!(
                matches!(out.delivery, AuditDelivery::SinkFailed(_)),
                "{r:?}"
            );
            assert_eq!(out.error, "rejected");
        }
        for r in [
            ViolationReason::RootfsMoved,
            ViolationReason::TargetMoved,
            ViolationReason::EntrypointIsRuntimeBinary,
        ] {
            let sink = VecSink::new(false);
            let out = record_exec_worker_rejection("x", r, None, &sink);
            assert_eq!(out.delivery, AuditDelivery::NotApplicable, "{r:?}");
            assert_eq!(sink.snapshot().len(), 0);
        }
    }

    /// SEC-4・SUP-6・TASK-163 追補・#1595: ExecError 入口は種別 Entrypoint のときだけ 1 件記録する。
    #[test]
    fn sec4_sup6_task163_audit_entrypoint_violation_records_once() {
        use crate::audit_log::mount::tests::VecSink;
        use crate::audit_log::{AuditDelivery, AuditLayer};
        use crate::exec::{ExecError, audit_entrypoint_violation};

        let sink = VecSink::new(false);
        let err = ExecError::from_violation_at(
            ViolationReason::EntrypointIsRuntimeBinary,
            None,
            IsolationStage::Exec,
        );
        let r = audit_entrypoint_violation(err, None, &sink);
        assert_eq!(r.delivery, AuditDelivery::Recorded);
        assert_eq!(
            r.error.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::EntrypointIsRuntimeBinary)
        );
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Entrypoint);

        let sys = ExecError::new(ErrorCode::Internal, IsolationStage::Exec, "sys");
        let r = audit_entrypoint_violation(sys, None, &sink);
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        let mount = ExecError::from_violation_at(
            ViolationReason::PathParentComponent,
            Some(Path::new("/a/../b")),
            IsolationStage::PrepareRootfs,
        );
        let r = audit_entrypoint_violation(mount, None, &sink);
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        assert_eq!(sink.snapshot().len(), 1);
    }

    /// SEC-4・TASK-41.4: audit_mount_violation は違反のみ記録し、エラーを変えない。
    #[test]
    fn sec4_task41_4_audit_mount_violation_records_once() {
        use crate::audit_log::mount::tests::VecSink;
        use crate::audit_log::{AuditDelivery, AuditLayer};
        use crate::exec::{ExecError, audit_mount_violation};

        let sink = VecSink::new(false);
        let err = ExecError::from_violation_at(
            ViolationReason::PathParentComponent,
            Some(Path::new("/tmp/a/../b")),
            IsolationStage::PrepareRootfs,
        );
        let cid = crate::traits::ContainerId::new("c1").unwrap();
        let r = audit_mount_violation(err, Some(&cid), &sink);
        assert_eq!(r.delivery, AuditDelivery::Recorded);
        assert_eq!(
            r.error.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathParentComponent)
        );
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(recs[0].path(), Some(Path::new("/tmp/a/../b")));
        assert_eq!(recs[0].container_id().map(|c| c.as_str()), Some("c1"));

        let sys = ExecError::new(ErrorCode::Internal, IsolationStage::MountProc, "sys");
        let r = audit_mount_violation(sys, None, &sink);
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        assert_eq!(sink.snapshot().len(), 1);
    }
}
