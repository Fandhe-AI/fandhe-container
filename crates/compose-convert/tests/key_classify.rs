//! キー分類表の公開 API を外から呼んで具体値で照合する結合試験
//! （STACK-3・TASK-151.2・#596・D-16・REPAIR-12）。`docs/spec` は参照しない。

use fandhe_container_compose_convert::classify::{
    KeyClass, classify_key_path, classify_network_mode_value, is_docker_socket_bind,
};

#[test]
fn static_classification_of_key_paths() {
    assert_eq!(classify_key_path("services.*"), KeyClass::Convert);
    assert_eq!(classify_key_path("name"), KeyClass::Convert);
    assert_eq!(classify_key_path("services.*.x-custom"), KeyClass::Warning);
    assert_eq!(
        classify_key_path("services.*.no_such_key"),
        KeyClass::Unrecognized
    );
    assert_eq!(classify_key_path("profiles"), KeyClass::ErrorUnsupportedYet);
    assert_eq!(
        classify_key_path("services.*.network_mode"),
        KeyClass::ErrorUnsupportedYet
    );
}

#[test]
fn vocabulary_and_severity_order() {
    assert_eq!(KeyClass::ErrorIncompatible.as_str(), "error-incompatible");
    assert_eq!(KeyClass::Unrecognized.to_string(), "unrecognized");
    assert!(KeyClass::Unrecognized.is_error());
    assert!(!KeyClass::Warning.is_error());
    assert_eq!(
        KeyClass::Convert.heavier(KeyClass::ErrorIncompatible),
        KeyClass::ErrorIncompatible
    );
}

#[test]
fn network_mode_value_classification() {
    assert_eq!(
        classify_network_mode_value(Some("host")),
        KeyClass::ErrorIncompatible
    );
    assert_eq!(
        classify_network_mode_value(Some("container:abc")),
        KeyClass::ErrorIncompatible
    );
    assert_eq!(
        classify_network_mode_value(Some("service:db")),
        KeyClass::ErrorUnsupportedYet
    );
    assert_eq!(
        classify_network_mode_value(None),
        KeyClass::ErrorUnsupportedYet
    );
}

#[test]
fn docker_socket_bind_detection() {
    assert!(is_docker_socket_bind(
        "/var/run/docker.sock:/var/run/docker.sock"
    ));
    assert!(is_docker_socket_bind("/var/run/docker.sock:/s:ro"));
    assert!(is_docker_socket_bind(
        "//./pipe/docker_engine://./pipe/docker_engine"
    ));
    assert!(!is_docker_socket_bind("./data:/data"));
    assert!(!is_docker_socket_bind(
        "/var/run/docker.sock.backup:/backup"
    ));
    assert!(!is_docker_socket_bind("./dummy:/var/run/docker.sock"));
}
