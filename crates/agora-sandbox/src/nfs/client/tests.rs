use super::RemoteClient;
use crate::nfs::protocol::{RemotePath, Request, Response};
use std::os::unix::net::UnixListener;
use std::time::Duration;

#[test]
fn client_rejects_a_missing_controller_socket() {
    let client = RemoteClient::new("/definitely/missing/agora.sock", "token");

    let error = client
        .request(Request::Stat {
            path: RemotePath::new(0, "file").unwrap(),
        })
        .unwrap_err();

    assert_eq!(error.errno(), libc::ENOENT);
}

#[test]
fn client_maps_remote_error_responses_to_errno() {
    let error = super::response_result(
        Response::Error {
            errno: libc::ESTALE,
            message: "changed".to_string(),
        },
        None,
    )
    .unwrap_err();

    assert_eq!(error.errno(), libc::ESTALE);
    assert_eq!(error.to_string(), "changed");
}

#[test]
fn client_times_out_when_the_broker_stops_responding() {
    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("nfs.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (release, wait) = std::sync::mpsc::sync_channel(0);
    let server = std::thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        wait.recv().unwrap();
    });
    let client = RemoteClient::new_with_timeout(&socket, "token", Duration::from_millis(25));

    let error = client
        .request(Request::Stat {
            path: RemotePath::new(0, "file").unwrap(),
        })
        .unwrap_err();

    assert_eq!(error.errno(), libc::ETIMEDOUT);
    release.send(()).unwrap();
    server.join().unwrap();
}
