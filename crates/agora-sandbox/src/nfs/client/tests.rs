use super::RemoteClient;
use crate::nfs::protocol::{
    PROTOCOL_VERSION, RemoteFileType, RemoteMetadata, RemotePath, Request, RequestEnvelope,
    RequestId, Response, ResponseEnvelope,
};
use crate::nfs::transport;
use std::io::{Read, Seek};
use std::os::fd::AsRawFd;
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

#[test]
fn client_retries_an_ambiguous_request_with_the_same_request_id() {
    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("nfs.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        let (first_request, descriptor) =
            transport::receive::<RequestEnvelope>(&mut first).unwrap();
        assert!(descriptor.is_none());
        drop(first);

        let (mut second, _) = listener.accept().unwrap();
        let (second_request, descriptor) =
            transport::receive::<RequestEnvelope>(&mut second).unwrap();
        assert!(descriptor.is_none());
        assert_eq!(second_request.request_id, first_request.request_id);
        transport::send(
            &mut second,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: second_request.request_id,
                response: Response::Success,
            },
            None,
        )
        .unwrap();
    });
    let client = RemoteClient::new_with_timeout(&socket, "token", Duration::from_millis(100));

    let reply = client
        .request(Request::Stat {
            path: RemotePath::new(0, "file").unwrap(),
        })
        .unwrap();

    assert_eq!(reply.response, Response::Success);
    server.join().unwrap();
}

fn metadata() -> RemoteMetadata {
    RemoteMetadata {
        file_type: RemoteFileType::File,
        size: 4,
        modified_seconds: 1,
        modified_nanoseconds: 0,
        identity: "1".to_string(),
    }
}

#[test]
fn client_claims_open_resources_before_returning_the_descriptor() {
    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("nfs.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut open_stream, _) = listener.accept().unwrap();
        let (open, descriptor) = transport::receive::<RequestEnvelope>(&mut open_stream).unwrap();
        assert!(descriptor.is_none());
        let mut contents = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut contents, b"data").unwrap();
        contents.rewind().unwrap();
        transport::send(
            &mut open_stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: open.request_id.clone(),
                response: Response::Open {
                    handle: "handle".to_string(),
                    metadata: metadata(),
                },
            },
            Some(contents.as_raw_fd()),
        )
        .unwrap();

        let (mut claim_stream, _) = listener.accept().unwrap();
        let (claim, descriptor) = transport::receive::<RequestEnvelope>(&mut claim_stream).unwrap();
        assert!(descriptor.is_none());
        assert_eq!(
            claim.request,
            Request::Claim {
                request_id: open.request_id,
            }
        );
        transport::send(
            &mut claim_stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: claim.request_id,
                response: Response::Success,
            },
            None,
        )
        .unwrap();
    });
    let client = RemoteClient::new(&socket, "token");

    let reply = client
        .request(Request::Open {
            path: RemotePath::new(0, "file").unwrap(),
            flags: libc::O_RDONLY,
            mode: 0,
        })
        .unwrap();
    let mut file = std::fs::File::from(reply.descriptor.unwrap());
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "data");
    server.join().unwrap();
}

#[test]
fn failed_open_claim_aborts_the_unaccepted_handle() {
    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("nfs.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut open_stream, _) = listener.accept().unwrap();
        let (open, _) = transport::receive::<RequestEnvelope>(&mut open_stream).unwrap();
        let contents = tempfile::tempfile().unwrap();
        transport::send(
            &mut open_stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: open.request_id,
                response: Response::Open {
                    handle: "unclaimed".to_string(),
                    metadata: metadata(),
                },
            },
            Some(contents.as_raw_fd()),
        )
        .unwrap();

        let (mut claim_stream, _) = listener.accept().unwrap();
        let (claim, _) = transport::receive::<RequestEnvelope>(&mut claim_stream).unwrap();
        transport::send(
            &mut claim_stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: claim.request_id,
                response: Response::Error {
                    errno: libc::EIO,
                    message: "claim failed".to_string(),
                },
            },
            None,
        )
        .unwrap();

        let (mut abort_stream, _) = listener.accept().unwrap();
        let (abort, _) = transport::receive::<RequestEnvelope>(&mut abort_stream).unwrap();
        assert_eq!(
            abort.request,
            Request::Abort {
                handle: "unclaimed".to_string(),
            }
        );
        transport::send(
            &mut abort_stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: abort.request_id,
                response: Response::Success,
            },
            None,
        )
        .unwrap();
    });
    let client = RemoteClient::new(&socket, "token");

    let error = client
        .request(Request::Open {
            path: RemotePath::new(0, "file").unwrap(),
            flags: libc::O_RDONLY,
            mode: 0,
        })
        .unwrap_err();
    assert_eq!(error.errno(), libc::EIO);
    server.join().unwrap();
}

#[test]
fn failed_anchor_claim_removes_the_unaccepted_anchor() {
    let runtime = tempfile::tempdir().unwrap();
    let anchor = "anchor-test";
    std::fs::write(runtime.path().join(anchor), b"").unwrap();
    let socket = runtime.path().join("nfs.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stat_stream, _) = listener.accept().unwrap();
        let (stat, _) = transport::receive::<RequestEnvelope>(&mut stat_stream).unwrap();
        transport::send(
            &mut stat_stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: stat.request_id,
                response: Response::Stat {
                    metadata: metadata(),
                    anchor: anchor.to_string(),
                },
            },
            None,
        )
        .unwrap();

        let (mut claim_stream, _) = listener.accept().unwrap();
        let (claim, _) = transport::receive::<RequestEnvelope>(&mut claim_stream).unwrap();
        transport::send(
            &mut claim_stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: claim.request_id,
                response: Response::Error {
                    errno: libc::EIO,
                    message: "claim failed".to_string(),
                },
            },
            None,
        )
        .unwrap();
    });
    let client = RemoteClient::new(&socket, "token");

    assert_eq!(
        client
            .request(Request::Stat {
                path: RemotePath::new(0, "file").unwrap(),
            })
            .unwrap_err()
            .errno(),
        libc::EIO
    );
    assert!(!runtime.path().join(anchor).exists());
    server.join().unwrap();
}

#[test]
fn client_rejects_response_version_id_and_descriptor_mismatches() {
    for mismatch in 0..2 {
        let runtime = tempfile::tempdir().unwrap();
        let socket = runtime.path().join("nfs.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (request, _) = transport::receive::<RequestEnvelope>(&mut stream).unwrap();
            transport::send(
                &mut stream,
                &ResponseEnvelope {
                    version: if mismatch == 0 {
                        PROTOCOL_VERSION + 1
                    } else {
                        PROTOCOL_VERSION
                    },
                    request_id: if mismatch == 1 {
                        RequestId::new("ffffffffffffffffffffffffffffffff").unwrap()
                    } else {
                        request.request_id
                    },
                    response: Response::Success,
                },
                None,
            )
            .unwrap();
        });
        let client = RemoteClient::new(&socket, "token");
        assert_eq!(
            client
                .request(Request::Access {
                    path: RemotePath::new(0, "file").unwrap(),
                    mode: libc::R_OK,
                })
                .unwrap_err()
                .errno(),
            libc::EPROTO
        );
        server.join().unwrap();
    }

    assert_eq!(
        super::response_result(
            Response::Open {
                handle: "handle".to_string(),
                metadata: metadata(),
            },
            None,
        )
        .unwrap_err()
        .errno(),
        libc::EPROTO
    );
    assert_eq!(
        super::response_result(
            Response::Success,
            Some(tempfile::tempfile().unwrap().into()),
        )
        .unwrap_err()
        .errno(),
        libc::EPROTO
    );
    super::remove_anchor(None, "unused");
}
