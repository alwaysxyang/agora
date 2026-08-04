use super::super::protocol::{
    AuditEventRequest, AuditResponse, decode_request, encode_response, frame_length,
};
use super::{AuditClient, AuditError, io};
use crate::callback::{FileAccessMode, FileContext, FileOpenMode, ProcessContext};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

struct PublishOnDrop {
    client: AuditClient,
    published: Arc<AtomicBool>,
}

impl Drop for PublishOnDrop {
    fn drop(&mut self) {
        let published = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.client.publish(file_request("/during-tls-destruction"))
        }))
        .is_ok_and(|result| result.is_ok());
        self.published.store(published, Ordering::Release);
    }
}

thread_local! {
    static DROP_PUBLISHER: RefCell<Option<PublishOnDrop>> = const { RefCell::new(None) };
}

fn file_request(path: &str) -> AuditEventRequest {
    AuditEventRequest::File {
        trace_id: "trace".to_string(),
        process: ProcessContext {
            pid: 42,
            ppid: 1,
            executable: "/bin/tool".to_string(),
        },
        operation: super::super::protocol::FileOperation::Open,
        file: FileContext {
            path: path.to_string(),
            mode: FileOpenMode {
                access: FileAccessMode::Read,
                create: false,
                truncate: false,
                append: false,
                exclusive: false,
            },
        },
    }
}

fn read_request(stream: &mut TcpStream) -> io::Result<()> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix)?;
    let mut frame = vec![0_u8; frame_length(prefix)?];
    stream.read_exact(&mut frame)?;
    decode_request(&frame)?;
    Ok(())
}

fn accept_request(listener: &TcpListener) -> io::Result<TcpStream> {
    let (mut stream, _) = listener.accept()?;
    read_request(&mut stream)?;
    stream.write_all(&encode_response(&AuditResponse::Accepted)?)?;
    Ok(stream)
}

#[test]
fn audit_error_maps_io_failures_to_stable_errno_values() {
    for (kind, expected) in [
        (io::ErrorKind::PermissionDenied, libc::EACCES),
        (io::ErrorKind::InvalidInput, libc::EINVAL),
        (io::ErrorKind::InvalidData, libc::EINVAL),
        (io::ErrorKind::TimedOut, libc::ETIMEDOUT),
        (io::ErrorKind::ConnectionRefused, libc::EIO),
    ] {
        let error = AuditError::from_io(io::Error::new(kind, "audit failure"));
        assert_eq!(error.errno(), expected);
        assert_eq!(error.to_string(), "audit failure");
    }

    let error = AuditError::from_io(io::Error::from_raw_os_error(libc::ECONNRESET));
    assert_eq!(error.errno(), libc::ECONNRESET);
}

#[test]
fn audit_client_reuses_one_connection_for_multiple_events() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut stream = accept_request(&listener).unwrap();
        match read_request(&mut stream) {
            Ok(()) => {
                stream
                    .write_all(&encode_response(&AuditResponse::Accepted).unwrap())
                    .unwrap();
                1
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                accept_request(&listener).unwrap();
                2
            }
            Err(error) => panic!("failed to read second audit request: {error}"),
        }
    });
    let client = AuditClient::new(address, "token");

    client.publish(file_request("/first")).unwrap();
    client.publish(file_request("/second")).unwrap();

    assert_eq!(server.join().unwrap(), 1);
}

#[test]
fn audit_client_publishes_after_its_thread_local_cache_is_destroyed() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        drop(accept_request(&listener).unwrap());
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    read_request(&mut stream).unwrap();
                    stream
                        .write_all(&encode_response(&AuditResponse::Accepted).unwrap())
                        .unwrap();
                    return 2;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("failed to accept fallback audit request: {error}"),
            }
        }
        1
    });
    let published = Arc::new(AtomicBool::new(false));
    let thread_published = Arc::clone(&published);

    std::thread::spawn(move || {
        let client = AuditClient::new(address, "token");
        DROP_PUBLISHER.with(|publisher| {
            *publisher.borrow_mut() = Some(PublishOnDrop {
                client: client.clone(),
                published: thread_published,
            });
        });
        client
            .publish(file_request("/before-tls-destruction"))
            .unwrap();
    })
    .join()
    .unwrap();

    assert!(published.load(Ordering::Acquire));
    assert_eq!(server.join().unwrap(), 2);
}
