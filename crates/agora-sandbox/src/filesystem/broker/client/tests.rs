use super::*;
use crate::filesystem::broker::protocol::{RequestEnvelope, ResponseEnvelope};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;

fn serve(
    listener: UnixListener,
    response: impl FnOnce(RequestEnvelope) -> (ResponseEnvelope, Option<std::fs::File>) + Send + 'static,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (request, descriptor) = ipc::receive::<RequestEnvelope>(&mut stream).unwrap();
        assert!(descriptor.is_none());
        let (response, descriptor) = response(request);
        ipc::send(
            &mut stream,
            &response,
            descriptor.as_ref().map(AsRawFd::as_raw_fd),
        )
        .unwrap();
    })
}

#[test]
fn client_retries_idempotent_requests_and_preserves_the_request_id() {
    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut first_stream, _) = listener.accept().unwrap();
        let (first, descriptor) = ipc::receive::<RequestEnvelope>(&mut first_stream).unwrap();
        assert!(descriptor.is_none());
        drop(first_stream);

        let (mut second_stream, _) = listener.accept().unwrap();
        let (second, descriptor) = ipc::receive::<RequestEnvelope>(&mut second_stream).unwrap();
        assert!(descriptor.is_none());
        assert_eq!(first.request_id, second.request_id);
        assert_eq!(first.request, second.request);
        ipc::send(
            &mut second_stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: second.request_id,
                response: Response::Success,
            },
            None,
        )
        .unwrap();
    });
    let client = LocalClient::new(&socket, "token");

    client
        .sync("handle", vec![ByteRange::new(1, 3).unwrap()], false)
        .unwrap();
    server.join().unwrap();
}

#[test]
fn client_rejects_mismatched_and_descriptor_bearing_responses() {
    for descriptor_response in [false, true] {
        let runtime = tempfile::tempdir().unwrap();
        let socket = runtime.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = serve(listener, move |request| {
            let descriptor = descriptor_response.then(|| tempfile::tempfile().unwrap());
            (
                ResponseEnvelope {
                    version: if descriptor_response {
                        PROTOCOL_VERSION
                    } else {
                        PROTOCOL_VERSION + 1
                    },
                    request_id: request.request_id,
                    response: Response::Success,
                },
                descriptor,
            )
        });
        let client = LocalClient::new(&socket, "token");

        let error = client.close("handle").unwrap_err();

        assert_eq!(error.errno(), libc::EPROTO);
        server.join().unwrap();
    }
}

#[test]
fn client_rejects_unexpected_success_shapes_and_maps_broker_errors() {
    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = serve(listener, |request| {
        (
            ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: request.request_id,
                response: Response::Open {
                    handle: "unexpected".to_string(),
                },
            },
            None,
        )
    });
    let client = LocalClient::new(&socket, "token");
    let error = client.close("handle").unwrap_err();
    assert_eq!(error.errno(), libc::EPROTO);
    server.join().unwrap();

    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = serve(listener, |request| {
        (
            ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: request.request_id,
                response: Response::Error {
                    errno: libc::ENOSPC,
                    message: "disk full".to_string(),
                },
            },
            None,
        )
    });
    let client = LocalClient::new(&socket, "token");
    let error = client.close("handle").unwrap_err();
    assert_eq!(error.errno(), libc::ENOSPC);
    assert_eq!(error.to_string(), "disk full");
    server.join().unwrap();
}

#[test]
fn client_open_validates_its_response_and_missing_sockets_keep_errno() {
    let runtime = tempfile::tempdir().unwrap();
    let socket = runtime.path().join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let (request, descriptor) = ipc::receive::<RequestEnvelope>(&mut stream).unwrap();
        assert!(descriptor.is_some());
        ipc::send(
            &mut stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                request_id: request.request_id,
                response: Response::Success,
            },
            None,
        )
        .unwrap();
    });
    let client = LocalClient::new(&socket, "token");
    let plaintext = tempfile::tempfile().unwrap();
    let error = match client.open(Path::new("/tmp/backing"), plaintext.as_raw_fd(), true) {
        Ok(_) => panic!("unexpected valid open response"),
        Err(error) => error,
    };
    assert_eq!(error.errno(), libc::EPROTO);
    server.join().unwrap();

    let missing = LocalClient::new(runtime.path().join("missing.sock"), "token");
    let error = missing.close("handle").unwrap_err();
    assert_eq!(error.errno(), libc::ENOENT);
    assert!(error.to_string().contains("connect"));
    assert!(format!("{error:?}").contains("LocalClientError"));
}

#[test]
fn retaining_no_handles_is_a_noop() {
    let client = LocalClient::new("/missing", "token");
    client.retain(Vec::new()).unwrap();
}
