//! containerd Task API のメッセージ型（Create / Start / Delete / Exec / Wait / State / Kill / Shutdown 分。CRI-5・TASK-62.2・TASK-62.3.1・TASK-62.3.2・TASK-62.4・TASK-62.7.2・MS-7）。
//!
//! containerd の `api/runtime/task/v2/shim.proto`（commit `aefce4e7cdbf9a8ce754cd4edb1de5d44f0c704d`）と
//! `api/types/mount.proto`・`api/types/task/task.proto`（`Status` enum）のフィールド番号を prost の derive で手書きする。`.proto` は持ち込まない
//! （#670。取り込みと SPDX・NOTICE の扱いは #669 で決める）。同 commit で v3 の `shim.proto` と diff した
//! ところ `package` と `go_package` の 2 行以外は同一だったため、1 組の型で v2 / v3 の両サービスを扱える
//! （版はサービス名だけで区別する。決定は #669）。
//!
//! `CreateTaskRequest.options`（`google.protobuf.Any`、番号 10）は意図して定義しない。定義しないと
//! prost は無言で読み飛ばすため、[`super::task_service`] が復号前の走査で存在を検出して拒否する（REPAIR-3）。

/// `containerd.types.Mount`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct Mount {
    /// ファイルシステムの種別。
    #[prost(string, tag = "1")]
    pub r#type: String,
    /// マウント元。
    #[prost(string, tag = "2")]
    pub source: String,
    /// マウント先。
    #[prost(string, tag = "3")]
    pub target: String,
    /// オプション。
    #[prost(string, repeated, tag = "4")]
    pub options: Vec<String>,
}

/// `CreateTaskRequest`（番号 1〜9。10 の `options` は定義しない）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct CreateTaskRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// OCI bundle のパス。
    #[prost(string, tag = "2")]
    pub bundle: String,
    /// rootfs の mount 一覧。未対応で、1 件でもあれば拒否する。
    #[prost(message, repeated, tag = "3")]
    pub rootfs: Vec<Mount>,
    /// pty の要否。未対応。
    #[prost(bool, tag = "4")]
    pub terminal: bool,
    /// stdin の FIFO。未対応。
    #[prost(string, tag = "5")]
    pub stdin: String,
    /// stdout の FIFO。未対応。
    #[prost(string, tag = "6")]
    pub stdout: String,
    /// stderr の FIFO。未対応。
    #[prost(string, tag = "7")]
    pub stderr: String,
    /// checkpoint。未対応。
    #[prost(string, tag = "8")]
    pub checkpoint: String,
    /// 親 checkpoint。未対応。
    #[prost(string, tag = "9")]
    pub parent_checkpoint: String,
}

/// `CreateTaskResponse`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct CreateTaskResponse {
    /// init プロセスの PID。0 は「不明」（proto3 の既定値）。
    #[prost(uint32, tag = "1")]
    pub pid: u32,
}

/// `StartRequest`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct StartRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// exec の ID。空でなければ、`Exec` で登録済みの exec プロセスの開始（TASK-62.4）。
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

/// `StartResponse`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct StartResponse {
    /// init プロセスの PID。0 は「不明」。
    #[prost(uint32, tag = "1")]
    pub pid: u32,
}

/// `google.protobuf.Timestamp`（`prost-types` を足さないための手書き）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct Timestamp {
    /// UNIX epoch からの秒。
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    /// 秒未満のナノ秒。
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

impl Timestamp {
    /// UNIX epoch からの経過時間から作る。秒は `i64` へ飽和させる（`unwrap` を使わない）。
    pub fn from_unix_duration(d: std::time::Duration) -> Self {
        Self {
            seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            // subsec_nanos は 10 億未満で i32 に収まる。
            nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        }
    }
}

/// `DeleteRequest`（Delete RPC。TASK-62.3.1）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct DeleteRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// exec の ID。空でなければ exec の削除（#674、未対応）。
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

/// `DeleteResponse`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct DeleteResponse {
    /// 削除したプロセスの PID。0 は「不明」。
    #[prost(uint32, tag = "1")]
    pub pid: u32,
    /// 終了コード。
    #[prost(uint32, tag = "2")]
    pub exit_status: u32,
    /// 終了時刻。core が記録した終了検知時刻で、停止済みのときだけ。未記録・未停止は未設定（#3682）。
    #[prost(message, optional, tag = "3")]
    pub exited_at: Option<Timestamp>,
}

/// `WaitRequest`（Wait RPC。TASK-62.3.2）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct WaitRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// exec の ID。空でなければ exec の待ち（未対応）。
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

/// `WaitResponse`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct WaitResponse {
    /// 終了コード。
    #[prost(uint32, tag = "1")]
    pub exit_status: u32,
    /// 終了時刻。core が記録した終了検知時刻で、停止済みのときだけ。未記録・未停止は未設定（#3682）。
    #[prost(message, optional, tag = "2")]
    pub exited_at: Option<Timestamp>,
}

/// `google.protobuf.Any`（`type_url` と `value` のみ。`Exec` の `spec` の運搬用）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct Any {
    /// 型 URL。
    #[prost(string, tag = "1")]
    pub type_url: String,
    /// 符号化済みの値。
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

/// `ExecProcessRequest`（TASK-62.4）。containerd の `shim.proto`（上記 commit）の番号 1〜7。
///
/// `Exec` は exec プロセスを登録するだけで、起動は続く `Start`（`exec_id` つき）が行う。
#[derive(Clone, PartialEq, prost::Message)]
pub struct ExecProcessRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// exec の ID。
    #[prost(string, tag = "2")]
    pub exec_id: String,
    /// pty の要否。未対応。
    #[prost(bool, tag = "3")]
    pub terminal: bool,
    /// stdin の FIFO。未対応。
    #[prost(string, tag = "4")]
    pub stdin: String,
    /// stdout の FIFO。未対応。
    #[prost(string, tag = "5")]
    pub stdout: String,
    /// stderr の FIFO。未対応。
    #[prost(string, tag = "6")]
    pub stderr: String,
    /// OCI runtime-spec の `Process`（JSON）を包んだ `Any`。
    #[prost(message, optional, tag = "7")]
    pub spec: Option<Any>,
}

/// `containerd.v1.types.Status`（State の応答の状態。番号は `api/types/task/task.proto`）。
///
/// `Paused` / `Pausing` は core に対応が無く shim は返さない。
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum TaskStatus {
    /// 不明。
    Unknown = 0,
    /// 作成済み・未起動。
    Created = 1,
    /// 実行中。
    Running = 2,
    /// 停止済み。
    Stopped = 3,
    /// 一時停止（未対応）。
    Paused = 4,
    /// 一時停止中（未対応）。
    Pausing = 5,
}

/// `StateRequest`（State RPC。TASK-62.7.2）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct StateRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// exec の ID。空でなければ exec の状態（未対応）。
    #[prost(string, tag = "2")]
    pub exec_id: String,
}

/// `StateResponse`。
///
/// `bundle`・stdio・`terminal`・`exec_id` は shim が持たないため常に空・未設定（REPAIR-3）。
/// `exited_at` は STOPPED で core が終了検知時刻を記録していたときだけ返す（#3682）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct StateResponse {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// bundle のパス。未提供（空）。
    #[prost(string, tag = "2")]
    pub bundle: String,
    /// init プロセスの PID。0 は「不明」。
    #[prost(uint32, tag = "3")]
    pub pid: u32,
    /// 状態（[`TaskStatus`] の値）。
    #[prost(enumeration = "TaskStatus", tag = "4")]
    pub status: i32,
    /// stdin の FIFO。未対応（空）。
    #[prost(string, tag = "5")]
    pub stdin: String,
    /// stdout の FIFO。未対応（空）。
    #[prost(string, tag = "6")]
    pub stdout: String,
    /// stderr の FIFO。未対応（空）。
    #[prost(string, tag = "7")]
    pub stderr: String,
    /// pty の要否。未対応（false）。
    #[prost(bool, tag = "8")]
    pub terminal: bool,
    /// 終了コード（停止済みのときだけ意味を持つ）。
    #[prost(uint32, tag = "9")]
    pub exit_status: u32,
    /// 終了時刻。STOPPED で core が記録していたときだけ（未記録は未設定。#3682）。
    #[prost(message, optional, tag = "10")]
    pub exited_at: Option<Timestamp>,
    /// exec の ID。常に空。
    #[prost(string, tag = "11")]
    pub exec_id: String,
}

/// `ConnectRequest`（Connect RPC。TASK-62.6・CRI-5）。
///
/// containerd は Create の直後（`shimTask.PID`）と Wait の前に呼ぶ。出典: containerd
/// `api/runtime/task/v2/shim.proto`（v2.1.4）の `ConnectRequest`。
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConnectRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
}

/// `ConnectResponse`。`version` は containerd が使わないため常に空（REPAIR-3）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConnectResponse {
    /// shim デーモン自身の PID。
    #[prost(uint32, tag = "1")]
    pub shim_pid: u32,
    /// init プロセスの PID。0 は「未起動または不明」。
    #[prost(uint32, tag = "2")]
    pub task_pid: u32,
    /// shim の版。常に空。
    #[prost(string, tag = "3")]
    pub version: String,
}

/// `KillRequest`（Kill RPC。TASK-62.7.2）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct KillRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// exec の ID。空でなければ exec への送信（未対応）。
    #[prost(string, tag = "2")]
    pub exec_id: String,
    /// シグナル番号。
    #[prost(uint32, tag = "3")]
    pub signal: u32,
    /// 全プロセスへ送るか。core は init にしか送れないため真は拒否する。
    #[prost(bool, tag = "4")]
    pub all: bool,
}

/// `ShutdownRequest`（Shutdown RPC。TASK-62.7.2）。
#[derive(Clone, PartialEq, prost::Message)]
pub struct ShutdownRequest {
    /// コンテナ ID。
    #[prost(string, tag = "1")]
    pub id: String,
    /// コンテナが残っていても終了するか。
    #[prost(bool, tag = "2")]
    pub now: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    /// CRI-5（#3682）: `Timestamp::from_unix_duration` は秒・ナノ秒を具体値で写し、秒は飽和する。
    #[test]
    fn cri5_3682_timestamp_from_unix_duration() {
        use std::time::Duration;
        assert_eq!(
            Timestamp::from_unix_duration(Duration::new(1_700_000_000, 999_999_999)),
            Timestamp {
                seconds: 1_700_000_000,
                nanos: 999_999_999
            }
        );
        assert_eq!(
            Timestamp::from_unix_duration(Duration::new(u64::MAX, 7)),
            Timestamp {
                seconds: i64::MAX,
                nanos: 7
            }
        );
    }

    /// CRI-5: フィールド番号の固定バイト列と往復。
    #[test]
    fn cri5_task_api_wire_bytes() {
        let r = CreateTaskRequest {
            id: "a".into(),
            bundle: "/b".into(),
            ..Default::default()
        };
        assert_eq!(r.encode_to_vec(), [0x0a, 1, b'a', 0x12, 2, b'/', b'b']);
        assert_eq!(
            CreateTaskRequest::decode(&r.encode_to_vec()[..]).unwrap(),
            r
        );
        assert_eq!(StartResponse { pid: 7 }.encode_to_vec(), [0x08, 7]);
        assert_eq!(CreateTaskResponse { pid: 7 }.encode_to_vec(), [0x08, 7]);
        let s = StartRequest {
            id: "a".into(),
            exec_id: "e".into(),
        };
        assert_eq!(s.encode_to_vec(), [0x0a, 1, b'a', 0x12, 1, b'e']);
    }

    /// CRI-5: Mount の 4 欄と rootfs（番号 3）・terminal（4）・stdin（5）の番号。
    #[test]
    fn cri5_mount_and_field_numbers() {
        let m = Mount {
            r#type: "t".into(),
            source: "s".into(),
            target: "g".into(),
            options: vec!["o".into()],
        };
        assert_eq!(
            m.encode_to_vec(),
            [0x0a, 1, b't', 0x12, 1, b's', 0x1a, 1, b'g', 0x22, 1, b'o']
        );
        let r = CreateTaskRequest {
            rootfs: vec![Mount::default()],
            terminal: true,
            stdin: "i".into(),
            ..Default::default()
        };
        assert_eq!(r.encode_to_vec(), [0x1a, 0, 0x20, 1, 0x2a, 1, b'i']);
    }

    /// CRI-5: Delete の固定バイト列と往復。
    #[test]
    fn cri5_delete_wire_bytes() {
        let r = DeleteRequest {
            id: "a".into(),
            exec_id: "e".into(),
        };
        assert_eq!(r.encode_to_vec(), [0x0a, 1, b'a', 0x12, 1, b'e']);
        assert_eq!(DeleteRequest::decode(&r.encode_to_vec()[..]).unwrap(), r);
        let mut d = DeleteResponse {
            pid: 7,
            exit_status: 3,
            exited_at: None,
        };
        assert_eq!(d.encode_to_vec(), [0x08, 7, 0x10, 3]);
        d.exited_at = Some(Timestamp {
            seconds: 1,
            nanos: 2,
        });
        let bytes = d.encode_to_vec();
        assert_eq!(bytes, [0x08, 7, 0x10, 3, 0x1a, 4, 0x08, 1, 0x10, 2]);
        assert_eq!(DeleteResponse::decode(&bytes[..]).unwrap(), d);
    }

    /// CRI-5: Wait の固定バイト列と往復。
    #[test]
    fn cri5_wait_wire_bytes() {
        let r = WaitRequest {
            id: "a".into(),
            exec_id: "e".into(),
        };
        assert_eq!(r.encode_to_vec(), [0x0a, 1, b'a', 0x12, 1, b'e']);
        assert_eq!(WaitRequest::decode(&r.encode_to_vec()[..]).unwrap(), r);
        let mut w = WaitResponse {
            exit_status: 3,
            exited_at: None,
        };
        assert_eq!(w.encode_to_vec(), [0x08, 3]);
        w.exited_at = Some(Timestamp {
            seconds: 1,
            nanos: 2,
        });
        let bytes = w.encode_to_vec();
        assert_eq!(bytes, [0x08, 3, 0x12, 4, 0x08, 1, 0x10, 2]);
        assert_eq!(WaitResponse::decode(&bytes[..]).unwrap(), w);
    }

    /// CRI-5: ExecProcessRequest と Any の番号。
    #[test]
    fn cri5_exec_request_wire_bytes() {
        let r = ExecProcessRequest {
            id: "a".into(),
            exec_id: "e".into(),
            terminal: true,
            stdin: "i".into(),
            stdout: "o".into(),
            stderr: "r".into(),
            spec: Some(Any {
                type_url: "u".into(),
                value: vec![9],
            }),
        };
        assert_eq!(
            r.encode_to_vec(),
            [
                0x0a, 1, b'a', 0x12, 1, b'e', 0x18, 1, 0x22, 1, b'i', 0x2a, 1, b'o', 0x32, 1, b'r',
                0x3a, 6, 0x0a, 1, b'u', 0x12, 1, 9
            ]
        );
        assert_eq!(
            ExecProcessRequest::decode(&r.encode_to_vec()[..]).unwrap(),
            r
        );
    }

    /// CRI-5・TASK-62.7.2: State / Kill / Shutdown の番号の固定バイト列。
    #[test]
    fn cri5_873_state_kill_shutdown_wire_bytes() {
        let r = StateRequest {
            id: "a".into(),
            exec_id: "e".into(),
        };
        assert_eq!(r.encode_to_vec(), [0x0a, 1, b'a', 0x12, 1, b'e']);
        let s = StateResponse {
            id: "a".into(),
            bundle: "b".into(),
            pid: 7,
            status: TaskStatus::Stopped as i32,
            stdin: "i".into(),
            stdout: "o".into(),
            stderr: "r".into(),
            terminal: true,
            exit_status: 3,
            exited_at: Some(Timestamp {
                seconds: 1,
                nanos: 2,
            }),
            exec_id: "x".into(),
        };
        assert_eq!(
            s.encode_to_vec(),
            [
                0x0a, 1, b'a', 0x12, 1, b'b', 0x18, 7, 0x20, 3, 0x2a, 1, b'i', 0x32, 1, b'o', 0x3a,
                1, b'r', 0x40, 1, 0x48, 3, 0x52, 4, 0x08, 1, 0x10, 2, 0x5a, 1, b'x'
            ]
        );
        assert_eq!(StateResponse::decode(&s.encode_to_vec()[..]).unwrap(), s);
        let k = KillRequest {
            id: "a".into(),
            exec_id: "e".into(),
            signal: 15,
            all: true,
        };
        assert_eq!(
            k.encode_to_vec(),
            [0x0a, 1, b'a', 0x12, 1, b'e', 0x18, 15, 0x20, 1]
        );
        let d = ShutdownRequest {
            id: "a".into(),
            now: true,
        };
        assert_eq!(d.encode_to_vec(), [0x0a, 1, b'a', 0x10, 1]);
        assert_eq!(
            [
                TaskStatus::Unknown as i32,
                TaskStatus::Created as i32,
                TaskStatus::Running as i32,
                TaskStatus::Stopped as i32
            ],
            [0, 1, 2, 3]
        );
    }
}
