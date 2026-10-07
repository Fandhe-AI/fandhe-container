//! コンテナ状態の `inspect` 相当の機械可読出力（SUP-11・TASK-168.1・#523・MS-9）。
//!
//! 自動化・AI 自己補修（REPAIR-4）や将来の CLI `inspect` 相当コマンドから呼ばれ、`state.json` の
//! 1 レコードを 1 個の JSON オブジェクトへ整形する。CLI への配線は未実装（本モジュールは出力生成のみ）。
//! 出力を機械的にパースして型・値を検証する結合テストは `tests/inspect_output.rs` に置く（#524・TASK-168.2 の
//! 受け入れ条件に相当する検証を本モジュールと併せて先行追加した）。
//!
//! 契約:
//! - 読み取りは core の [`StateStore`] 経由のみで、`state.json` の復号・所有者 / 権限 / symlink / サイズ上限 /
//!   ロック待ち上限（REPAIR-5）の検査は core 側の実装に委ねる。本モジュールは 2 つ目の復号実装・状態型を
//!   持たない（crate-naming.md 決定 6・TASK-157.3・OCI-5）。状態は書き換えない。
//! - キー名は `state.json` と同じ camelCase。spec の `supervisor_pid` / `restart_count` は論理名で、
//!   出力キーは `supervisorPid` / `restartCount` になる。
//! - 値を持たない項目はキーを省略せず `null` を出す（`state.json` は `None` を書かない点との差。項目の
//!   存在を機械照合できるようにするため）。
//! - 出力は 1 個の JSON オブジェクト + 末尾 LF 1 個（1 行。改行は LF 固定）。キー順は固定。
//! - `supervisorPid`・`pid` は記録値でありシグナル送信先・権限判断に使わない（SUP-5・SUP-8）。
//! - Linux 以外では core が `Unimplemented` を返し、そのまま伝播する（CLI-1）。
//! - 出力は有界: ID 255 バイト・bundle / cgroupScope 各 4096 バイト以下（core が検証）、
//!   エスケープで最大 6 倍。untrusted 値（bundle・cgroupScope）は必ずエスケープする。

use std::fmt::Write as _;
use std::io;
use std::num::NonZeroU32;
use std::path::Path;

use fandhe_container_core::traits::{
    CgroupPlacement, ContainerId, ContainerState, ErrorCode, GetStateRequest, HealthStatus,
    StateRecord, StateRevision, StateStore, TraitError,
};

/// bundle・cgroupScope の最大バイト数（出力有界化の上限。core の `state.json` 検証値と揃える）。
const MAX_FIELD_BYTES: usize = 4096;

/// 1 コンテナ分の inspect 出力の内容（SUP-11）。[`StateRecord`] のスナップショット。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InspectReport {
    record: StateRecord,
}

impl InspectReport {
    /// レコードから出力内容を作る。
    ///
    /// 公開 API 経由の任意の [`StateRecord`] でも出力サイズを有界に保つため、bundle・cgroupScope が
    /// 各 [`MAX_FIELD_BYTES`] バイトを超えるレコードは [`ErrorCode::InvalidArgument`] で拒否する
    /// （`StateRecord::new` は絶対パスしか検証しない。無制限確保の防止。SUP-11・TASK-168.1）。
    /// また bundle が UTF-8 でない場合も拒否する（`to_string_lossy` が不正バイトを置換文字へ変え、
    /// 元のパスと一致しない値を黙って出力するのを防ぐ。core の state.json も同入力を拒否する）。
    /// ID は [`ContainerId`] 構築時に 255 バイト以下へ検証済み。
    pub fn from_record(record: &StateRecord) -> Result<Self, TraitError> {
        if record.bundle().to_str().is_none() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "bundle path must be valid UTF-8",
            ));
        }
        if record.bundle().as_os_str().len() > MAX_FIELD_BYTES {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("bundle path must be at most {MAX_FIELD_BYTES} bytes"),
            ));
        }
        if let Some(c) = record.cgroup()
            && c.scope().as_str().len() > MAX_FIELD_BYTES
        {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("cgroup scope must be at most {MAX_FIELD_BYTES} bytes"),
            ));
        }
        Ok(Self {
            record: record.clone(),
        })
    }

    /// コンテナ ID。
    pub fn id(&self) -> &ContainerId {
        self.record.id()
    }

    /// コンテナ状態。
    pub fn status(&self) -> ContainerState {
        self.record.status().state()
    }

    /// init プロセスの PID（記録値）。
    pub fn pid(&self) -> Option<NonZeroU32> {
        self.record.status().pid()
    }

    /// 終了コード。
    pub fn exit_code(&self) -> Option<i32> {
        self.record.status().exit_code()
    }

    /// OCI bundle の絶対パス。
    pub fn bundle(&self) -> &Path {
        self.record.bundle()
    }

    /// レコードの revision。
    pub fn revision(&self) -> StateRevision {
        self.record.revision()
    }

    /// cgroup の配置。
    pub fn cgroup(&self) -> Option<&CgroupPlacement> {
        self.record.cgroup()
    }

    /// 監視プロセスの PID（記録値。SUP-5・SUP-8 のとおり信頼しない）。
    pub fn supervisor_pid(&self) -> Option<NonZeroU32> {
        self.record.supervisor_pid()
    }

    /// healthcheck の結果。
    pub fn health(&self) -> Option<HealthStatus> {
        self.record.health()
    }

    /// 再起動回数。
    pub fn restart_count(&self) -> u32 {
        self.record.restart_count()
    }

    /// 1 個の JSON オブジェクト（末尾改行なし）へ整形する。
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push_str("{\"id\":");
        push_str_value(&mut s, self.id().as_str());
        s.push_str(",\"status\":");
        push_str_value(&mut s, self.status().as_str());
        s.push_str(",\"pid\":");
        push_opt_num(&mut s, self.pid().map(NonZeroU32::get));
        s.push_str(",\"exitCode\":");
        match self.exit_code() {
            Some(c) => {
                let _ = write!(s, "{c}");
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"bundle\":");
        push_str_value(&mut s, &self.bundle().to_string_lossy());
        let _ = write!(s, ",\"revision\":{}", self.revision().value());
        s.push_str(",\"cgroupScope\":");
        match self.cgroup() {
            Some(c) => push_str_value(&mut s, c.scope().as_str()),
            None => s.push_str("null"),
        }
        s.push_str(",\"cgroupInstance\":");
        match self.cgroup() {
            Some(c) => {
                let _ = write!(s, "{}", c.instance().value());
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"supervisorPid\":");
        push_opt_num(&mut s, self.supervisor_pid().map(NonZeroU32::get));
        s.push_str(",\"health\":");
        match self.health() {
            Some(h) => push_str_value(&mut s, h.as_str()),
            None => s.push_str("null"),
        }
        let _ = write!(s, ",\"restartCount\":{}", self.restart_count());
        s.push('}');
        s
    }

    /// [`Self::to_json`] に LF を 1 個付けて書き出す。
    pub fn write_json(&self, w: &mut impl io::Write) -> io::Result<()> {
        let mut line = self.to_json();
        line.push('\n');
        w.write_all(line.as_bytes())
    }
}

/// ストアから 1 件読んで [`InspectReport`] を作る（読み取りのみ）。
///
/// エラー（`NotFound`・破損の `Internal`・`PermissionDenied`・Linux 以外の `Unimplemented`）は
/// core の [`TraitError`] をそのまま返し、部分的な出力は作らない。
pub fn inspect(store: &dyn StateStore, id: &ContainerId) -> Result<InspectReport, TraitError> {
    let record = store.get(&GetStateRequest::new(id.clone()))?;
    InspectReport::from_record(&record)
}

fn push_opt_num(out: &mut String, v: Option<u32>) {
    match v {
        Some(n) => {
            let _ = write!(out, "{n}");
        }
        None => out.push_str("null"),
    }
}

fn push_str_value(out: &mut String, v: &str) {
    out.push('"');
    out.push_str(&json_escape(v));
    out.push('"');
}

/// JSON 文字列用のエスケープ（`"`・`\`・制御文字）。cli・io と同じ規則のローカル実装。
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{
        CgroupScope, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
        ListStateRequest, StateList, SupervisionState, UpdateStateRequest,
    };

    /// 固定レコードまたは固定エラーを返すメモリ上のフェイク。
    struct FakeStore(Result<StateRecord, ErrorCode>);

    fn unimpl() -> TraitError {
        TraitError::new(ErrorCode::Unimplemented, "fake")
    }

    impl StateStore for FakeStore {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(unimpl())
        }
        fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(unimpl())
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.0.clone().map_err(|c| TraitError::new(c, "fake error"))
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(unimpl())
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(unimpl())
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    fn nz(n: u32) -> Option<NonZeroU32> {
        NonZeroU32::new(n)
    }

    fn bundle() -> std::path::PathBuf {
        std::env::temp_dir().join("b")
    }

    #[test]
    fn sup11_task168_1_full_record_json_is_exact() {
        let b = bundle();
        let rec = StateRecord::new(
            ContainerStatus::running(cid("web-1"), nz(42)),
            b.clone(),
            StateRevision::from_raw(5),
        )
        .unwrap()
        .with_supervision(SupervisionState::new(nz(7), Some(HealthStatus::Healthy), 2));
        let expected = format!(
            "{{\"id\":\"web-1\",\"status\":\"running\",\"pid\":42,\"exitCode\":null,\"bundle\":\"{}\",\"revision\":5,\"cgroupScope\":null,\"cgroupInstance\":null,\"supervisorPid\":7,\"health\":\"healthy\",\"restartCount\":2}}",
            json_escape(&b.to_string_lossy())
        );
        assert_eq!(
            InspectReport::from_record(&rec).unwrap().to_json(),
            expected
        );
    }

    #[test]
    fn sup11_task168_1_absent_values_are_null() {
        let b = bundle();
        let rec = StateRecord::new(
            ContainerStatus::created(cid("c"), None),
            b.clone(),
            StateRevision::from_raw(1),
        )
        .unwrap();
        let expected = format!(
            "{{\"id\":\"c\",\"status\":\"created\",\"pid\":null,\"exitCode\":null,\"bundle\":\"{}\",\"revision\":1,\"cgroupScope\":null,\"cgroupInstance\":null,\"supervisorPid\":null,\"health\":null,\"restartCount\":0}}",
            json_escape(&b.to_string_lossy())
        );
        assert_eq!(
            InspectReport::from_record(&rec).unwrap().to_json(),
            expected
        );
    }

    #[test]
    fn sup11_task168_1_stopped_negative_exit_code_and_cgroup() {
        let b = bundle();
        let rec = StateRecord::new(
            ContainerStatus::stopped(cid("c"), Some(-9)),
            b.clone(),
            StateRevision::from_raw(3),
        )
        .unwrap()
        .with_cgroup(CgroupPlacement::new(
            CgroupScope::new("/a/b").unwrap(),
            StateRevision::from_raw(2),
        ));
        let expected = format!(
            "{{\"id\":\"c\",\"status\":\"stopped\",\"pid\":null,\"exitCode\":-9,\"bundle\":\"{}\",\"revision\":3,\"cgroupScope\":\"/a/b\",\"cgroupInstance\":2,\"supervisorPid\":null,\"health\":null,\"restartCount\":0}}",
            json_escape(&b.to_string_lossy())
        );
        assert_eq!(
            InspectReport::from_record(&rec).unwrap().to_json(),
            expected
        );
    }

    #[test]
    fn sup11_task168_1_from_record_rejects_oversized_bundle() {
        let ok = bundle().join("a".repeat(MAX_FIELD_BYTES - bundle().as_os_str().len() - 1));
        let mk = |b: std::path::PathBuf| {
            StateRecord::new(
                ContainerStatus::created(cid("c"), None),
                b,
                StateRevision::from_raw(1),
            )
            .unwrap()
        };
        assert!(InspectReport::from_record(&mk(ok.clone())).is_ok());
        let e = InspectReport::from_record(&mk(ok.join("x"))).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    #[cfg(unix)]
    #[test]
    fn sup11_task168_1_from_record_rejects_non_utf8_bundle() {
        use std::os::unix::ffi::OsStringExt;
        let mut raw = b"/b".to_vec();
        raw.push(0xff);
        let rec = StateRecord::new(
            ContainerStatus::created(cid("c"), None),
            std::path::PathBuf::from(std::ffi::OsString::from_vec(raw)),
            StateRevision::from_raw(1),
        )
        .unwrap();
        let e = InspectReport::from_record(&rec).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    #[test]
    fn sup11_task168_1_escape_is_exact() {
        assert_eq!(
            json_escape("a\"b\\c\nd\re\tf\u{1}"),
            "a\\\"b\\\\c\\nd\\re\\tf\\u0001"
        );
    }

    #[test]
    fn sup11_task168_1_untrusted_bundle_stays_one_line() {
        // StateRecord::new は絶対パスのみ許可するため、Windows でも絶対になる接頭辞を使う。
        let b = bundle().join("x\"y\nz\u{2}");
        let rec = StateRecord::new(
            ContainerStatus::created(cid("c"), None),
            b,
            StateRevision::from_raw(1),
        )
        .unwrap();
        let json = InspectReport::from_record(&rec).unwrap().to_json();
        assert!(json.contains("x\\\"y\\nz\\u0002\""), "{json}");
        assert!(!json.contains('\n'));
    }

    #[test]
    fn sup11_task168_1_write_json_appends_single_lf() {
        let rec = StateRecord::new(
            ContainerStatus::created(cid("c"), None),
            bundle(),
            StateRevision::from_raw(1),
        )
        .unwrap();
        let report = InspectReport::from_record(&rec).unwrap();
        let mut buf = Vec::new();
        report.write_json(&mut buf).unwrap();
        assert_eq!(buf, format!("{}\n", report.to_json()).into_bytes());
    }

    #[test]
    fn sup11_task168_1_inspect_reads_and_propagates_errors() {
        let rec = StateRecord::new(
            ContainerStatus::running(cid("c"), nz(9)),
            bundle(),
            StateRevision::from_raw(4),
        )
        .unwrap()
        .with_supervision(SupervisionState::new(
            nz(3),
            Some(HealthStatus::Starting),
            1,
        ));
        let r = inspect(&FakeStore(Ok(rec)), &cid("c")).unwrap();
        assert_eq!(r.id().as_str(), "c");
        assert_eq!(r.status(), ContainerState::Running);
        assert_eq!(r.pid(), nz(9));
        assert_eq!(r.revision().value(), 4);
        assert_eq!(r.supervisor_pid(), nz(3));
        assert_eq!(r.health(), Some(HealthStatus::Starting));
        assert_eq!(r.restart_count(), 1);

        for code in [ErrorCode::NotFound, ErrorCode::Internal] {
            let e = inspect(&FakeStore(Err(code)), &cid("c")).unwrap_err();
            assert_eq!(e.code(), code);
        }
    }
}
