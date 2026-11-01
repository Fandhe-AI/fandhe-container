//! containerd Task API のメッセージ型（Create / Start / Delete / Exec 分。CRI-5・TASK-62.2・TASK-62.3.1・TASK-62.4・MS-7）。
//!
//! containerd の `api/runtime/task/v2/shim.proto`（commit `aefce4e7cdbf9a8ce754cd4edb1de5d44f0c704d`）と
//! `api/types/mount.proto` のフィールド番号を prost の derive で手書きする。`.proto` は持ち込まない
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
    /// 終了時刻。core が持たないため現状は常に未設定（REPAIR-3）。
    #[prost(message, optional, tag = "3")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

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
}
