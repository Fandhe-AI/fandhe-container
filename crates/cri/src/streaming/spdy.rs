//! SPDY/3.1 のフレーム符号化・復号とヘッダブロックの zlib 圧縮（CRI-6・TASK-63.2・#680・REPAIR-2）。
//!
//! kubelet / apiserver の remotecommand（Exec・Attach）と portforward は、HTTP/1.1 Upgrade（`SPDY/3.1`）の後に
//! SPDY/3 のフレームで多重化した複数ストリームを流す。本モジュールはそのうち CRI のストリーミングサーバーが使う部分
//! （SYN_STREAM・SYN_REPLY・RST_STREAM・SETTINGS・PING・GOAWAY・HEADERS・WINDOW_UPDATE・DATA）を、生のバイト列を
//! 手で組まない型（[`Frame`]・[`StreamId`]・[`RstStatus`]）で表す。呼び出し元は [`super::exec`]（#680）で、
//! Attach（#681）・PortForward（#682）も同じ型を使う想定である（共通化の候補はこのモジュールの全体）。
//!
//! ## 外部入力としての扱い
//!
//! 受信バイトは untrusted である。フレーム長・ヘッダ個数・展開後サイズは確保の前に上限を見る
//! （[`MAX_CONTROL_FRAME_BYTES`]・[`MAX_DATA_FRAME_BYTES`]・[`MAX_HEADER_COUNT`]・[`MAX_HEADER_BLOCK_BYTES`]）。
//! 復号は panic せず [`ProtocolError`] を返す。
//!
//! ## 辞書の出典
//!
//! ヘッダブロックの zlib 辞書は SPDY Protocol Draft 3（draft-mbelshe-httpbis-spdy-00, 2012-02）§2.6.10.1 の
//! `SPDY_dictionary_txt`（1423 バイト）を、IETF 掲載のテキストから機械的に起こしたものである。
//! 長さと Adler-32（0xe3c6a7c2）は試験で照合する。ライセンス・帰属表示の要否は PR 本文で報告する（licensing.md）。

use std::fmt;

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};

/// 制御フレームのペイロード長の上限（バイト）。確保の前に検査する。
pub const MAX_CONTROL_FRAME_BYTES: usize = 16 * 1024;
/// DATA フレームのペイロード長の上限（バイト）。client-go の stdin は 32 KiB 単位である。
pub const MAX_DATA_FRAME_BYTES: usize = 256 * 1024;
/// ヘッダブロック 1 つあたりのヘッダ個数の上限。
pub const MAX_HEADER_COUNT: usize = 32;
/// ヘッダ名・値それぞれの長さの上限（バイト）。
pub const MAX_HEADER_FIELD_BYTES: usize = 4 * 1024;
/// 展開後のヘッダブロックの合計サイズの上限（バイト。zlib bomb 対策）。
pub const MAX_HEADER_BLOCK_BYTES: usize = 64 * 1024;

/// 制御フレームの先頭 2 バイト（C ビット + version 3）。
const CONTROL_VERSION: u16 = 0x8003;
const FLAG_FIN: u8 = 0x01;
const FLAG_UNIDIRECTIONAL: u8 = 0x02;

const TYPE_SYN_STREAM: u16 = 1;
const TYPE_SYN_REPLY: u16 = 2;
const TYPE_RST_STREAM: u16 = 3;
const TYPE_SETTINGS: u16 = 4;
const TYPE_PING: u16 = 6;
const TYPE_GOAWAY: u16 = 7;
const TYPE_HEADERS: u16 = 8;
const TYPE_WINDOW_UPDATE: u16 = 9;

/// SPDY/3 のヘッダブロック用 zlib 辞書の Adler-32。
pub const SPDY3_DICT_ADLER32: u32 = 0xe3c6_a7c2;

/// SPDY/3 のヘッダブロック用 zlib 辞書（1423 バイト）。出典はモジュール doc を参照。
#[rustfmt::skip]
pub const SPDY3_DICT: [u8; 1423] = [
    0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68,
    0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70,
    0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05,
    0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00, 0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00,
    0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65,
    0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f,
    0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c,
    0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00, 0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70,
    0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00,
    0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68,
    0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63,
    0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f,
    0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74,
    0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74,
    0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10,
    0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,
    0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67,
    0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f,
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
    0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
    0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
    0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00, 0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00,
    0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00, 0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74,
    0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66,
    0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69,
    0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f,
    0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d,
    0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00,
    0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d,
    0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65,
    0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74, 0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,
    0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00,
    0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00,
    0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00, 0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79,
    0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00,
    0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00,
    0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72, 0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72,
    0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,
    0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00, 0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c,
    0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65,
    0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61,
    0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73, 0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74,
    0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79, 0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00,
    0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77,
    0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00,
    0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00,
    0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30,
    0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00,
    0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72,
    0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73,
    0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65,
    0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00, 0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69,
    0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32, 0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35,
    0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30, 0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33,
    0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37, 0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30,
    0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34, 0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31,
    0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31, 0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34,
    0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34, 0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e,
    0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65,
    0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20,
    0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f,
    0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34,
    0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30,
    0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30,
    0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e,
    0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64, 0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65,
    0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f,
    0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74, 0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65,
    0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20,
    0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46,
    0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41, 0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a,
    0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41, 0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20,
    0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20, 0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30,
    0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57,
    0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c, 0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61,
    0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20, 0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b,
    0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61,
    0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67,
    0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67, 0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69,
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c,
    0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74,
    0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c,
    0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65,
    0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64,
    0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63,
    0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69, 0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d,
    0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a, 0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e,
];

/// SPDY の規則違反（不正なフレーム・上限超え・展開の失敗）。メッセージは固定の英語文で、入力の内容を含めない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolError(&'static str);

impl ProtocolError {
    fn new(message: &'static str) -> Self {
        Self(message)
    }

    /// 固定の説明文。
    pub fn message(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spdy protocol error: {}", self.0)
    }
}

impl std::error::Error for ProtocolError {}

/// ストリーム ID（31 ビット、0 は不可）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u32);

impl StreamId {
    /// 0 と最上位ビットが立った値は作れない。
    pub fn new(value: u32) -> Option<Self> {
        if value == 0 || value & 0x8000_0000 != 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// 数値。
    pub fn get(self) -> u32 {
        self.0
    }

    /// クライアントが開始するストリーム（奇数）か。
    pub fn is_client_initiated(self) -> bool {
        self.0 % 2 == 1
    }
}

/// RST_STREAM の状態コード（SPDY/3 §2.6.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RstStatus {
    /// PROTOCOL_ERROR(1)。
    ProtocolError,
    /// INVALID_STREAM(2)。
    InvalidStream,
    /// REFUSED_STREAM(3)。
    RefusedStream,
    /// UNSUPPORTED_VERSION(4)。
    UnsupportedVersion,
    /// CANCEL(5)。
    Cancel,
    /// INTERNAL_ERROR(6)。
    InternalError,
    /// FLOW_CONTROL_ERROR(7)。
    FlowControlError,
    /// STREAM_IN_USE(8)。
    StreamInUse,
    /// STREAM_ALREADY_CLOSED(9)。
    StreamAlreadyClosed,
    /// INVALID_CREDENTIALS(10)。
    InvalidCredentials,
    /// FRAME_TOO_LARGE(11)。
    FrameTooLarge,
    /// 上記以外（相手が送った値を保持する）。
    Unknown(u32),
}

impl RstStatus {
    /// ワイヤ上の数値。
    pub fn code(self) -> u32 {
        match self {
            RstStatus::ProtocolError => 1,
            RstStatus::InvalidStream => 2,
            RstStatus::RefusedStream => 3,
            RstStatus::UnsupportedVersion => 4,
            RstStatus::Cancel => 5,
            RstStatus::InternalError => 6,
            RstStatus::FlowControlError => 7,
            RstStatus::StreamInUse => 8,
            RstStatus::StreamAlreadyClosed => 9,
            RstStatus::InvalidCredentials => 10,
            RstStatus::FrameTooLarge => 11,
            RstStatus::Unknown(v) => v,
        }
    }

    /// 数値から。
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => RstStatus::ProtocolError,
            2 => RstStatus::InvalidStream,
            3 => RstStatus::RefusedStream,
            4 => RstStatus::UnsupportedVersion,
            5 => RstStatus::Cancel,
            6 => RstStatus::InternalError,
            7 => RstStatus::FlowControlError,
            8 => RstStatus::StreamInUse,
            9 => RstStatus::StreamAlreadyClosed,
            10 => RstStatus::InvalidCredentials,
            11 => RstStatus::FrameTooLarge,
            other => RstStatus::Unknown(other),
        }
    }
}

/// GOAWAY の状態コード（SPDY/3 §2.6.6）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoAwayStatus {
    /// OK(0)。正常終了。
    Ok,
    /// PROTOCOL_ERROR(1)。
    ProtocolError,
    /// INTERNAL_ERROR(2)。
    InternalError,
    /// 上記以外。
    Unknown(u32),
}

impl GoAwayStatus {
    /// ワイヤ上の数値。
    pub fn code(self) -> u32 {
        match self {
            GoAwayStatus::Ok => 0,
            GoAwayStatus::ProtocolError => 1,
            GoAwayStatus::InternalError => 2,
            GoAwayStatus::Unknown(v) => v,
        }
    }

    /// 数値から。
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => GoAwayStatus::Ok,
            1 => GoAwayStatus::ProtocolError,
            2 => GoAwayStatus::InternalError,
            other => GoAwayStatus::Unknown(other),
        }
    }
}

/// ヘッダ 1 件。名前は小文字に正規化して保持する（SPDY/3 はヘッダ名を小文字で送る。spdystream も同じ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// 小文字化したヘッダ名。
    pub name: String,
    /// 値（NUL 区切りの複数値はそのまま）。
    pub value: String,
}

/// SPDY/3 のフレーム。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// SYN_STREAM（ストリームの開始）。
    SynStream {
        /// 新しいストリームの ID。
        stream_id: StreamId,
        /// 関連ストリームの ID（0 は無し）。
        associated_to: u32,
        /// 優先度（0〜7）。
        priority: u8,
        /// FIN フラグ。
        fin: bool,
        /// UNIDIRECTIONAL フラグ。
        unidirectional: bool,
        /// ヘッダ。
        headers: Vec<Header>,
    },
    /// SYN_REPLY（ストリームの受理）。
    SynReply {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// FIN フラグ。
        fin: bool,
        /// ヘッダ。
        headers: Vec<Header>,
    },
    /// RST_STREAM。
    RstStream {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// 理由。
        status: RstStatus,
    },
    /// SETTINGS（内容は使わない。件数だけ保持する）。
    Settings {
        /// エントリ数。
        entries: u32,
    },
    /// PING。
    Ping {
        /// ID。
        id: u32,
    },
    /// GOAWAY。
    GoAway {
        /// 処理した最後のストリーム ID。
        last_good_stream_id: u32,
        /// 理由。
        status: GoAwayStatus,
    },
    /// HEADERS。
    Headers {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// FIN フラグ。
        fin: bool,
        /// ヘッダ。
        headers: Vec<Header>,
    },
    /// WINDOW_UPDATE。
    WindowUpdate {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// 増分。
        delta: u32,
    },
    /// DATA。
    Data {
        /// 対象ストリーム。
        stream_id: StreamId,
        /// FIN フラグ。
        fin: bool,
        /// ペイロード。
        payload: Vec<u8>,
    },
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = buf.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    let bytes: [u8; 2] = buf.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// 受信側のヘッダブロック展開器。接続の間ずっと 1 本の zlib ストリームを続ける（SPDY/3 の規定）。
pub struct HeaderDecompressor {
    inner: Decompress,
}

impl fmt::Debug for HeaderDecompressor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HeaderDecompressor")
    }
}

impl Default for HeaderDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderDecompressor {
    /// 新しい展開器。
    pub fn new() -> Self {
        Self {
            inner: Decompress::new(true),
        }
    }

    /// ヘッダブロックを展開する。FDICT の DICTID が SPDY/3 の辞書と一致しなければ拒否する。
    /// 展開後サイズが [`MAX_HEADER_BLOCK_BYTES`] を超えたら途中で打ち切る。
    fn decompress(&mut self, block: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let mut out: Vec<u8> = Vec::new();
        let mut consumed = 0usize;
        // 無進捗の連続回数。辞書の要求を 1 回挟むため 2 回までは許す。
        let mut stalls = 0u32;
        loop {
            if out.len() > MAX_HEADER_BLOCK_BYTES {
                return Err(ProtocolError::new("header block too large"));
            }
            let room = MAX_HEADER_BLOCK_BYTES
                .saturating_add(1)
                .saturating_sub(out.len())
                .min(4096);
            out.reserve(room);
            let before_in = self.inner.total_in();
            let before_out = self.inner.total_out();
            let input = block.get(consumed..).unwrap_or(&[]);
            let result = self
                .inner
                .decompress_vec(input, &mut out, FlushDecompress::Sync);
            let used_in = usize::try_from(self.inner.total_in().saturating_sub(before_in))
                .map_err(|_| ProtocolError::new("header block too large"))?;
            let produced = self.inner.total_out().saturating_sub(before_out);
            consumed = consumed.saturating_add(used_in);
            match result {
                Ok(_) => {
                    if consumed >= block.len() && produced == 0 {
                        break;
                    }
                    if used_in == 0 && produced == 0 {
                        stalls += 1;
                        if stalls > 2 {
                            return Err(ProtocolError::new("header block is truncated"));
                        }
                    } else {
                        stalls = 0;
                    }
                }
                Err(e) => match e.needs_dictionary() {
                    Some(adler) => {
                        if adler != SPDY3_DICT_ADLER32 {
                            return Err(ProtocolError::new("unexpected zlib dictionary id"));
                        }
                        self.inner
                            .set_dictionary(&SPDY3_DICT)
                            .map_err(|_| ProtocolError::new("failed to set zlib dictionary"))?;
                        stalls += 1;
                        if stalls > 2 {
                            return Err(ProtocolError::new("header block is truncated"));
                        }
                    }
                    None => return Err(ProtocolError::new("invalid compressed header block")),
                },
            }
        }
        Ok(out)
    }
}

/// 展開済みヘッダブロック（`個数, (名前長, 名前, 値長, 値)*`）を解析する。
fn parse_header_block(raw: &[u8]) -> Result<Vec<Header>, ProtocolError> {
    let bad = || ProtocolError::new("malformed header block");
    let count = read_u32(raw, 0).ok_or_else(bad)?;
    let count = usize::try_from(count).map_err(|_| bad())?;
    if count > MAX_HEADER_COUNT {
        return Err(ProtocolError::new("too many headers"));
    }
    let mut pos = 4usize;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
        let mut fields: [&[u8]; 2] = [&[], &[]];
        for slot in &mut fields {
            let len = read_u32(raw, pos).ok_or_else(bad)?;
            let len = usize::try_from(len).map_err(|_| bad())?;
            if len > MAX_HEADER_FIELD_BYTES {
                return Err(ProtocolError::new("header field too long"));
            }
            let start = pos.checked_add(4).ok_or_else(bad)?;
            let end = start.checked_add(len).ok_or_else(bad)?;
            *slot = raw.get(start..end).ok_or_else(bad)?;
            pos = end;
        }
        let name = String::from_utf8_lossy(fields[0]).to_ascii_lowercase();
        let value = String::from_utf8_lossy(fields[1]).into_owned();
        headers.push(Header { name, value });
    }
    if pos != raw.len() {
        return Err(ProtocolError::new("trailing bytes in header block"));
    }
    Ok(headers)
}

fn stream_id_of(raw: u32) -> Result<StreamId, ProtocolError> {
    StreamId::new(raw & 0x7fff_ffff).ok_or_else(|| ProtocolError::new("invalid stream id"))
}

/// バッファ先頭から 1 フレームを取り出す。
///
/// - `Ok(Some((frame, consumed)))`: 復号できた。`consumed` バイトを呼び出し側が捨てる
/// - `Ok(None)`: まだバイトが足りない（読み足してから呼び直す）
/// - `Err(_)`: 不正。接続を閉じること
///
/// 長さの上限はヘッダ 8 バイトが揃った時点で、ペイロードの確保や展開の前に検査する。
/// ヘッダブロックを持つフレームは `headers` の展開器へ到着順に流す（zlib 文脈が接続で共有されるため）。
pub fn decode_frame(
    buf: &[u8],
    headers: &mut HeaderDecompressor,
) -> Result<Option<(Frame, usize)>, ProtocolError> {
    let Some(head) = buf.get(..8) else {
        return Ok(None);
    };
    let short_header = || ProtocolError::new("short header");
    let first = read_u32(head, 0).ok_or_else(short_header)?;
    let flags = *head.get(4).ok_or_else(short_header)?;
    let len = read_u32(head, 4).ok_or_else(short_header)? & 0x00ff_ffff;
    let len = usize::try_from(len).map_err(|_| short_header())?;
    let is_control = first & 0x8000_0000 != 0;

    if !is_control {
        if len > MAX_DATA_FRAME_BYTES {
            return Err(ProtocolError::new("data frame too large"));
        }
        let total = 8 + len;
        let Some(payload) = buf.get(8..total) else {
            return Ok(None);
        };
        let stream_id = stream_id_of(first)?;
        if flags & !FLAG_FIN != 0 {
            return Err(ProtocolError::new("unknown data flags"));
        }
        return Ok(Some((
            Frame::Data {
                stream_id,
                fin: flags & FLAG_FIN != 0,
                payload: payload.to_vec(),
            },
            total,
        )));
    }

    let version = read_u16(head, 0).ok_or_else(short_header)?;
    if version != CONTROL_VERSION {
        return Err(ProtocolError::new("unsupported spdy version"));
    }
    let ftype = read_u16(head, 2).ok_or_else(short_header)?;
    if len > MAX_CONTROL_FRAME_BYTES {
        return Err(ProtocolError::new("control frame too large"));
    }
    let total = 8 + len;
    let Some(payload) = buf.get(8..total) else {
        return Ok(None);
    };
    let short = || ProtocolError::new("control frame length mismatch");
    let frame = match ftype {
        TYPE_SYN_STREAM => {
            let id = read_u32(payload, 0).ok_or_else(short)?;
            let assoc = read_u32(payload, 4).ok_or_else(short)?;
            let prio_byte = *payload.get(8).ok_or_else(short)?;
            let block = payload.get(10..).ok_or_else(short)?;
            let raw = headers.decompress(block)?;
            Frame::SynStream {
                stream_id: stream_id_of(id)?,
                associated_to: assoc & 0x7fff_ffff,
                priority: prio_byte >> 5,
                fin: flags & FLAG_FIN != 0,
                unidirectional: flags & FLAG_UNIDIRECTIONAL != 0,
                headers: parse_header_block(&raw)?,
            }
        }
        TYPE_SYN_REPLY => {
            let id = read_u32(payload, 0).ok_or_else(short)?;
            let block = payload.get(4..).ok_or_else(short)?;
            let raw = headers.decompress(block)?;
            Frame::SynReply {
                stream_id: stream_id_of(id)?,
                fin: flags & FLAG_FIN != 0,
                headers: parse_header_block(&raw)?,
            }
        }
        TYPE_RST_STREAM => {
            if len != 8 {
                return Err(short());
            }
            let id = read_u32(payload, 0).ok_or_else(short)?;
            let status = read_u32(payload, 4).ok_or_else(short)?;
            Frame::RstStream {
                stream_id: stream_id_of(id)?,
                status: RstStatus::from_code(status),
            }
        }
        TYPE_SETTINGS => {
            let n = read_u32(payload, 0).ok_or_else(short)?;
            let expected = usize::try_from(n)
                .ok()
                .and_then(|n| n.checked_mul(8))
                .and_then(|b| b.checked_add(4));
            if expected != Some(len) {
                return Err(short());
            }
            Frame::Settings { entries: n }
        }
        TYPE_PING => {
            if len != 4 {
                return Err(short());
            }
            Frame::Ping {
                id: read_u32(payload, 0).ok_or_else(short)?,
            }
        }
        TYPE_GOAWAY => {
            if len != 8 {
                return Err(short());
            }
            Frame::GoAway {
                last_good_stream_id: read_u32(payload, 0).ok_or_else(short)? & 0x7fff_ffff,
                status: GoAwayStatus::from_code(read_u32(payload, 4).ok_or_else(short)?),
            }
        }
        TYPE_HEADERS => {
            let id = read_u32(payload, 0).ok_or_else(short)?;
            let block = payload.get(4..).ok_or_else(short)?;
            let raw = headers.decompress(block)?;
            Frame::Headers {
                stream_id: stream_id_of(id)?,
                fin: flags & FLAG_FIN != 0,
                headers: parse_header_block(&raw)?,
            }
        }
        TYPE_WINDOW_UPDATE => {
            if len != 8 {
                return Err(short());
            }
            let id = read_u32(payload, 0).ok_or_else(short)?;
            Frame::WindowUpdate {
                stream_id: stream_id_of(id)?,
                delta: read_u32(payload, 4).ok_or_else(short)? & 0x7fff_ffff,
            }
        }
        _ => return Err(ProtocolError::new("unknown control frame type")),
    };
    Ok(Some((frame, total)))
}

/// 送信側のフレーム符号化器。ヘッダブロックは接続の間続く 1 本の zlib ストリーム（辞書つき）で圧縮する。
pub struct FrameEncoder {
    compress: Compress,
}

impl fmt::Debug for FrameEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FrameEncoder")
    }
}

impl FrameEncoder {
    /// 新しい符号化器。zlib に SPDY/3 の辞書を設定する。
    pub fn new() -> Result<Self, ProtocolError> {
        let mut compress = Compress::new(Compression::default(), true);
        compress
            .set_dictionary(&SPDY3_DICT)
            .map_err(|_| ProtocolError::new("failed to set zlib dictionary"))?;
        Ok(Self { compress })
    }

    fn compress_block(&mut self, raw: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let mut out: Vec<u8> = Vec::new();
        let mut consumed = 0usize;
        loop {
            out.reserve(512);
            let before_in = self.compress.total_in();
            let input = raw.get(consumed..).unwrap_or(&[]);
            self.compress
                .compress_vec(input, &mut out, FlushCompress::Sync)
                .map_err(|_| ProtocolError::new("failed to compress header block"))?;
            let used = usize::try_from(self.compress.total_in().saturating_sub(before_in))
                .map_err(|_| ProtocolError::new("header block too large"))?;
            consumed = consumed.saturating_add(used);
            if consumed >= raw.len() && out.len() < out.capacity() {
                return Ok(out);
            }
            if out.len() > MAX_CONTROL_FRAME_BYTES {
                return Err(ProtocolError::new("header block too large"));
            }
        }
    }

    fn header_block(&mut self, headers: &[Header]) -> Result<Vec<u8>, ProtocolError> {
        if headers.len() > MAX_HEADER_COUNT {
            return Err(ProtocolError::new("too many headers"));
        }
        let mut raw = Vec::new();
        push_u32(
            &mut raw,
            u32::try_from(headers.len()).map_err(|_| ProtocolError::new("too many headers"))?,
        );
        for h in headers {
            for field in [h.name.as_bytes(), h.value.as_bytes()] {
                if field.len() > MAX_HEADER_FIELD_BYTES {
                    return Err(ProtocolError::new("header field too long"));
                }
                push_u32(
                    &mut raw,
                    u32::try_from(field.len())
                        .map_err(|_| ProtocolError::new("header field too long"))?,
                );
                raw.extend_from_slice(field);
            }
        }
        self.compress_block(&raw)
    }

    fn control(
        out: &mut Vec<u8>,
        ftype: u16,
        flags: u8,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        if payload.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(ProtocolError::new("control frame too large"));
        }
        let len = u32::try_from(payload.len())
            .map_err(|_| ProtocolError::new("control frame too large"))?;
        out.extend_from_slice(&CONTROL_VERSION.to_be_bytes());
        out.extend_from_slice(&ftype.to_be_bytes());
        out.push(flags);
        out.extend_from_slice(&len.to_be_bytes()[1..]);
        out.extend_from_slice(payload);
        Ok(())
    }

    /// フレームを符号化して `out` の末尾へ追加する。
    pub fn encode(&mut self, frame: &Frame, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        match frame {
            Frame::SynStream {
                stream_id,
                associated_to,
                priority,
                fin,
                unidirectional,
                headers,
            } => {
                let mut p = Vec::new();
                push_u32(&mut p, stream_id.get());
                push_u32(&mut p, *associated_to & 0x7fff_ffff);
                p.push((*priority & 0x07) << 5);
                p.push(0);
                p.extend_from_slice(&self.header_block(headers)?);
                let flags = (if *fin { FLAG_FIN } else { 0 })
                    | (if *unidirectional {
                        FLAG_UNIDIRECTIONAL
                    } else {
                        0
                    });
                Self::control(out, TYPE_SYN_STREAM, flags, &p)
            }
            Frame::SynReply {
                stream_id,
                fin,
                headers,
            } => {
                let mut p = Vec::new();
                push_u32(&mut p, stream_id.get());
                p.extend_from_slice(&self.header_block(headers)?);
                Self::control(out, TYPE_SYN_REPLY, if *fin { FLAG_FIN } else { 0 }, &p)
            }
            Frame::RstStream { stream_id, status } => {
                let mut p = Vec::new();
                push_u32(&mut p, stream_id.get());
                push_u32(&mut p, status.code());
                Self::control(out, TYPE_RST_STREAM, 0, &p)
            }
            Frame::Settings { entries } => {
                if *entries != 0 {
                    return Err(ProtocolError::new("settings entries are not supported"));
                }
                let mut p = Vec::new();
                push_u32(&mut p, 0);
                Self::control(out, TYPE_SETTINGS, 0, &p)
            }
            Frame::Ping { id } => {
                let mut p = Vec::new();
                push_u32(&mut p, *id);
                Self::control(out, TYPE_PING, 0, &p)
            }
            Frame::GoAway {
                last_good_stream_id,
                status,
            } => {
                let mut p = Vec::new();
                push_u32(&mut p, *last_good_stream_id & 0x7fff_ffff);
                push_u32(&mut p, status.code());
                Self::control(out, TYPE_GOAWAY, 0, &p)
            }
            Frame::Headers {
                stream_id,
                fin,
                headers,
            } => {
                let mut p = Vec::new();
                push_u32(&mut p, stream_id.get());
                p.extend_from_slice(&self.header_block(headers)?);
                Self::control(out, TYPE_HEADERS, if *fin { FLAG_FIN } else { 0 }, &p)
            }
            Frame::WindowUpdate { stream_id, delta } => {
                let mut p = Vec::new();
                push_u32(&mut p, stream_id.get());
                push_u32(&mut p, *delta & 0x7fff_ffff);
                Self::control(out, TYPE_WINDOW_UPDATE, 0, &p)
            }
            Frame::Data {
                stream_id,
                fin,
                payload,
            } => {
                if payload.len() > MAX_DATA_FRAME_BYTES {
                    return Err(ProtocolError::new("data frame too large"));
                }
                let len = u32::try_from(payload.len())
                    .map_err(|_| ProtocolError::new("data frame too large"))?;
                push_u32(out, stream_id.get());
                out.push(if *fin { FLAG_FIN } else { 0 });
                out.extend_from_slice(&len.to_be_bytes()[1..]);
                out.extend_from_slice(payload);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(v: u32) -> StreamId {
        StreamId::new(v).expect("stream id")
    }

    fn hdr(name: &str, value: &str) -> Header {
        Header {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    /// CRI-6・REPAIR-2: 辞書は 1423 バイトで、Adler-32 は別途（Rust の外で）計算した 0xe3c6a7c2 と一致する。
    /// 転記の誤りがあれば長さか Adler-32 のどちらかが崩れる。
    #[test]
    fn cri6_dictionary_length_and_adler32() {
        assert_eq!(SPDY3_DICT.len(), 1423);
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &byte in SPDY3_DICT.iter() {
            a = (a + u32::from(byte)) % 65521;
            b = (b + a) % 65521;
        }
        assert_eq!((b << 16) | a, 0xe3c6_a7c2);
        assert_eq!(SPDY3_DICT_ADLER32, 0xe3c6_a7c2);
        assert_eq!(&SPDY3_DICT[..11], b"\x00\x00\x00\x07options");
        assert_eq!(&SPDY3_DICT[SPDY3_DICT.len() - 10..], b"-,*,enq=0.");
    }

    /// CRI-6・REPAIR-2: 手で書いたバイト列と符号化の結果が一致する（ヘッダブロックを持たないフレーム）。
    #[test]
    fn cri6_fixed_frames_wire_bytes() {
        let mut enc = FrameEncoder::new().expect("encoder");
        let mut out = Vec::new();
        enc.encode(
            &Frame::RstStream {
                stream_id: sid(3),
                status: RstStatus::RefusedStream,
            },
            &mut out,
        )
        .expect("rst");
        assert_eq!(
            out,
            [
                0x80, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 3, 0, 0, 0, 3
            ]
        );
        out.clear();
        enc.encode(&Frame::Ping { id: 1 }, &mut out).expect("ping");
        assert_eq!(
            out,
            [0x80, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04, 0, 0, 0, 1]
        );
        out.clear();
        enc.encode(
            &Frame::GoAway {
                last_good_stream_id: 5,
                status: GoAwayStatus::Ok,
            },
            &mut out,
        )
        .expect("goaway");
        assert_eq!(
            out,
            [
                0x80, 0x03, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 5, 0, 0, 0, 0
            ]
        );
        out.clear();
        enc.encode(
            &Frame::Data {
                stream_id: sid(7),
                fin: true,
                payload: b"hi".to_vec(),
            },
            &mut out,
        )
        .expect("data");
        assert_eq!(out, [0, 0, 0, 7, 0x01, 0, 0, 2, b'h', b'i']);
        out.clear();
        enc.encode(
            &Frame::Data {
                stream_id: sid(7),
                fin: false,
                payload: Vec::new(),
            },
            &mut out,
        )
        .expect("empty data");
        assert_eq!(out, [0, 0, 0, 7, 0, 0, 0, 0]);
    }

    /// CRI-6: 手で書いた固定長フレームのバイト列を復号できる。
    #[test]
    fn cri6_decode_fixed_frames() {
        let mut dec = HeaderDecompressor::new();
        let ping = [0x80, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04, 0, 0, 0, 9];
        let (frame, used) = decode_frame(&ping, &mut dec).expect("ok").expect("some");
        assert_eq!((frame, used), (Frame::Ping { id: 9 }, 12));
        let wu = [
            0x80, 0x03, 0x00, 0x09, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 2, 0, 0, 1, 0,
        ];
        let (frame, _) = decode_frame(&wu, &mut dec).expect("ok").expect("some");
        assert_eq!(
            frame,
            Frame::WindowUpdate {
                stream_id: sid(2),
                delta: 256
            }
        );
        let data = [0, 0, 0, 1, 0x01, 0, 0, 3, b'a', b'b', b'c', 0xff];
        let (frame, used) = decode_frame(&data, &mut dec).expect("ok").expect("some");
        assert_eq!(used, 11);
        assert_eq!(
            frame,
            Frame::Data {
                stream_id: sid(1),
                fin: true,
                payload: b"abc".to_vec()
            }
        );
        let settings = [
            0x80, 0x03, 0x00, 0x04, 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 100,
        ];
        let (frame, used) = decode_frame(&settings, &mut dec)
            .expect("ok")
            .expect("some");
        assert_eq!((frame, used), (Frame::Settings { entries: 1 }, 20));
    }

    /// CRI-6・REPAIR-5: 不足は `Ok(None)`、不正（version・type・長さ・上限超え）は確保の前に `Err`。
    #[test]
    fn cri6_decode_incomplete_and_invalid() {
        let mut dec = HeaderDecompressor::new();
        assert_eq!(decode_frame(&[0x80, 0x03], &mut dec), Ok(None));
        let ping = [0x80, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04, 0, 0];
        assert_eq!(decode_frame(&ping, &mut dec), Ok(None));
        // version 違い。
        let v2 = [0x80, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04, 0, 0, 0, 1];
        assert!(decode_frame(&v2, &mut dec).is_err());
        // 未知の type。
        let t99 = [0x80, 0x03, 0x00, 0x63, 0x00, 0x00, 0x00, 0x00];
        assert!(decode_frame(&t99, &mut dec).is_err());
        // PING の長さ違い。
        let p8 = [
            0x80, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0, 0, 0, 1, 0, 0, 0, 1,
        ];
        assert!(decode_frame(&p8, &mut dec).is_err());
        // 制御フレームの上限超え。ペイロードが無くてもヘッダの時点で拒否する（確保の前）。
        let big_ctl = [0x80, 0x03, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff];
        assert_eq!(
            decode_frame(&big_ctl, &mut dec).unwrap_err().message(),
            "control frame too large"
        );
        // DATA の上限超え。
        let big_data = [0, 0, 0, 1, 0x00, 0xff, 0xff, 0xff];
        assert_eq!(
            decode_frame(&big_data, &mut dec).unwrap_err().message(),
            "data frame too large"
        );
        // stream id 0。
        let zero = [0, 0, 0, 0, 0x00, 0, 0, 0];
        assert!(decode_frame(&zero, &mut dec).is_err());
        // DATA の未知フラグ。
        let flag = [0, 0, 0, 1, 0x04, 0, 0, 0];
        assert!(decode_frame(&flag, &mut dec).is_err());
        // SETTINGS の件数と長さの不一致。
        let st = [0x80, 0x03, 0x00, 0x04, 0, 0, 0, 4, 0, 0, 0, 5];
        assert!(decode_frame(&st, &mut dec).is_err());
    }

    /// CRI-6・REPAIR-2: ヘッダブロックを 1 本の zlib ストリームで 3 ブロック続けて往復できる。
    /// 先頭のブロックは辞書つきの zlib ヘッダ（FDICT）で始まり、DICTID は辞書の Adler-32 と一致する。
    #[test]
    fn cri6_header_blocks_roundtrip_three_in_one_stream() {
        let mut enc = FrameEncoder::new().expect("encoder");
        let mut dec = HeaderDecompressor::new();
        let frames = vec![
            Frame::SynStream {
                stream_id: sid(1),
                associated_to: 0,
                priority: 2,
                fin: false,
                unidirectional: false,
                headers: vec![hdr("streamtype", "error")],
            },
            Frame::SynReply {
                stream_id: sid(1),
                fin: false,
                headers: vec![],
            },
            Frame::Headers {
                stream_id: sid(3),
                fin: true,
                headers: vec![hdr("a", "b"), hdr("streamtype", "stdout")],
            },
        ];
        let mut wire = Vec::new();
        for f in &frames {
            enc.encode(f, &mut wire).expect("encode");
        }
        // 最初のヘッダブロックの zlib ヘッダ: FLG は FDICT(0x20) を立て、続く 4 バイトが DICTID。
        let block0 = wire.get(8 + 10..).expect("first block");
        assert_eq!(block0.get(1).copied().expect("flg") & 0x20, 0x20);
        assert_eq!(block0.get(2..6).expect("dictid"), [0xe3, 0xc6, 0xa7, 0xc2]);
        let mut pos = 0;
        let mut got = Vec::new();
        while pos < wire.len() {
            let (f, used) = decode_frame(wire.get(pos..).expect("rest"), &mut dec)
                .expect("decode")
                .expect("complete");
            got.push(f);
            pos += used;
        }
        assert_eq!(got, frames);
    }

    /// CRI-6: ヘッダ名は小文字に正規化される。
    #[test]
    fn cri6_header_names_lowercased() {
        let mut enc = FrameEncoder::new().expect("encoder");
        let mut dec = HeaderDecompressor::new();
        let mut wire = Vec::new();
        enc.encode(
            &Frame::SynReply {
                stream_id: sid(2),
                fin: false,
                headers: vec![hdr("StreamType", "stdin")],
            },
            &mut wire,
        )
        .expect("encode");
        let (f, _) = decode_frame(&wire, &mut dec).expect("ok").expect("some");
        match f {
            Frame::SynReply { headers, .. } => {
                assert_eq!(headers, vec![hdr("streamtype", "stdin")])
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    fn wrap_synreply(block: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        push_u32(&mut p, 1);
        p.extend_from_slice(block);
        let mut out = Vec::new();
        FrameEncoder::control(&mut out, TYPE_SYN_REPLY, 0, &p).expect("control");
        out
    }

    /// 新しい符号化器で生の（展開済み）ヘッダブロックを圧縮して SYN_REPLY に包み、新しい展開器で復号する。
    fn decode_raw_block(raw: &[u8]) -> Result<Option<(Frame, usize)>, ProtocolError> {
        let mut enc = FrameEncoder::new().expect("encoder");
        let block = enc.compress_block(raw).expect("compress");
        decode_frame(&wrap_synreply(&block), &mut HeaderDecompressor::new())
    }

    /// CRI-6・REPAIR-5: 個数の上限超え・不正な長さ・余りを `Err` にする。
    #[test]
    fn cri6_malformed_header_blocks_rejected() {
        let mut too_many = Vec::new();
        push_u32(&mut too_many, 33);
        assert_eq!(
            decode_raw_block(&too_many).unwrap_err().message(),
            "too many headers"
        );

        let mut short = Vec::new();
        push_u32(&mut short, 1);
        assert_eq!(
            decode_raw_block(&short).unwrap_err().message(),
            "malformed header block"
        );

        let mut trailing = Vec::new();
        push_u32(&mut trailing, 1);
        push_u32(&mut trailing, 1);
        trailing.push(b'a');
        push_u32(&mut trailing, 1);
        trailing.push(b'b');
        trailing.push(0);
        assert_eq!(
            decode_raw_block(&trailing).unwrap_err().message(),
            "trailing bytes in header block"
        );

        let mut huge_len = Vec::new();
        push_u32(&mut huge_len, 1);
        push_u32(&mut huge_len, 0xffff_ffff);
        assert_eq!(
            decode_raw_block(&huge_len).unwrap_err().message(),
            "header field too long"
        );
    }

    /// CRI-6・REPAIR-5: 展開後の上限を超える細工ブロック（zlib bomb）は途中で打ち切って `Err`。
    #[test]
    fn cri6_decompression_bomb_rejected() {
        // 値を 1 つの巨大な繰り返しにすると、展開後は数 MiB でも圧縮後は数 KiB に収まる。
        let big = vec![b'a'; 4 * 1024 * 1024];
        let mut raw = Vec::new();
        push_u32(&mut raw, 1);
        push_u32(&mut raw, 1);
        raw.push(b'x');
        push_u32(&mut raw, u32::try_from(big.len()).expect("len"));
        raw.extend_from_slice(&big);
        let mut enc = FrameEncoder::new().expect("encoder");
        let block = enc.compress_block(&raw).expect("compress");
        assert!(
            block.len() < MAX_CONTROL_FRAME_BYTES,
            "bomb must fit a control frame"
        );
        let wire = wrap_synreply(&block);
        let mut dec = HeaderDecompressor::new();
        assert_eq!(
            decode_frame(&wire, &mut dec).unwrap_err().message(),
            "header block too large"
        );
    }

    /// CRI-6: 辞書の ID が違う zlib ストリームは拒否する。
    #[test]
    fn cri6_wrong_dictionary_rejected() {
        let mut c = Compress::new(Compression::default(), true);
        c.set_dictionary(b"some other dictionary").expect("dict");
        let mut raw = Vec::new();
        push_u32(&mut raw, 0);
        let mut block = Vec::with_capacity(256);
        c.compress_vec(&raw, &mut block, FlushCompress::Sync)
            .expect("compress");
        let wire = wrap_synreply(&block);
        let mut dec = HeaderDecompressor::new();
        assert_eq!(
            decode_frame(&wire, &mut dec).unwrap_err().message(),
            "unexpected zlib dictionary id"
        );
    }

    /// CRI-6: ストリーム ID の newtype は 0 と最上位ビットを作れない。
    #[test]
    fn cri6_stream_id_bounds() {
        assert!(StreamId::new(0).is_none());
        assert!(StreamId::new(0x8000_0000).is_none());
        assert_eq!(
            StreamId::new(0x7fff_ffff).map(StreamId::get),
            Some(0x7fff_ffff)
        );
        assert!(sid(1).is_client_initiated());
        assert!(!sid(2).is_client_initiated());
    }
}
