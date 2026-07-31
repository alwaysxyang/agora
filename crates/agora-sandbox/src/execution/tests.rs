use super::ExecutionController;
use super::protocol::{
    PrepareRequest, PrepareResponse, decode_prepare_request, decode_prepare_response,
    encode_prepare_request, encode_prepare_response, frame_length,
};
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("agora-execution-test-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn cache(&self) -> PathBuf {
        self.0.join("cache")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn body(frame: &[u8]) -> &[u8] {
    let length = frame_length(frame[..4].try_into().unwrap()).unwrap();
    assert_eq!(length, frame.len() - 4);
    &frame[4..]
}

#[test]
fn execution_prepare_protocol_preserves_paths() {
    let request = encode_prepare_request("token", Path::new("/tmp/客户端")).unwrap();
    assert_eq!(
        decode_prepare_request(body(&request)).unwrap(),
        PrepareRequest {
            token: "token".to_string(),
            executable: PathBuf::from("/tmp/客户端"),
        }
    );

    let response =
        encode_prepare_response(&PrepareResponse::Ready(PathBuf::from("/tmp/agora/curl"))).unwrap();
    assert_eq!(
        decode_prepare_response(body(&response)).unwrap(),
        PrepareResponse::Ready(PathBuf::from("/tmp/agora/curl"))
    );
}

#[test]
fn execution_prepare_protocol_rejects_invalid_frames() {
    assert!(encode_prepare_request("", Path::new("/bin/bash")).is_err());
    assert!(decode_prepare_request(&[]).is_err());
    assert!(decode_prepare_response(&[]).is_err());
    assert!(frame_length(0_u32.to_be_bytes()).is_err());
    assert!(frame_length(u32::MAX.to_be_bytes()).is_err());

    let response = encode_prepare_response(&PrepareResponse::Error {
        errno: libc::EACCES,
        message: "denied".to_string(),
    })
    .unwrap();
    assert_eq!(
        decode_prepare_response(body(&response)).unwrap(),
        PrepareResponse::Error {
            errno: libc::EACCES,
            message: "denied".to_string(),
        }
    );
}

#[test]
fn execution_prepare_protocol_rejects_malformed_requests() {
    let mut unsupported =
        body(&encode_prepare_request("token", Path::new("/bin/sh")).unwrap()).to_vec();
    unsupported[1] = 3;
    assert!(decode_prepare_request(&unsupported).is_err());

    let mut invalid_lengths =
        body(&encode_prepare_request("token", Path::new("/bin/sh")).unwrap()).to_vec();
    invalid_lengths[2..4].copy_from_slice(&0_u16.to_be_bytes());
    assert!(decode_prepare_request(&invalid_lengths).is_err());

    let invalid_token = [0, 1, 0, 1, 0, 0, 0, 1, 0xff, b'x'];
    assert!(decode_prepare_request(&invalid_token).is_err());
}

#[test]
fn execution_prepare_protocol_rejects_malformed_responses() {
    let ready = encode_prepare_response(&PrepareResponse::Ready(PathBuf::from("/bin/sh"))).unwrap();
    let mut unsupported = body(&ready).to_vec();
    unsupported[1] = 3;
    assert!(decode_prepare_response(&unsupported).is_err());

    let mut invalid_length = body(&ready).to_vec();
    invalid_length[3..7].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_prepare_response(&invalid_length).is_err());

    let mut invalid_status = body(&ready).to_vec();
    invalid_status[2] = 2;
    assert!(decode_prepare_response(&invalid_status).is_err());

    let invalid_error = [0, 2, 1, 0, 0, 0, 5, 0, 0, 0, 1, 0xff];
    assert!(decode_prepare_response(&invalid_error).is_err());
    let truncated_error = [0, 2, 1, 0, 0, 0, 3, 0, 0, 0];
    assert!(decode_prepare_response(&truncated_error).is_err());
    let invalid_errno = [0, 2, 1, 0, 0, 0, 4, 0, 0, 0, 0];
    assert!(decode_prepare_response(&invalid_errno).is_err());

    let oversized = OsString::from_vec(vec![b'x'; 64 * 1024]);
    assert!(
        encode_prepare_request("token", Path::new(&oversized)).is_err(),
        "the protocol must reject a body larger than its frame limit"
    );
    assert!(
        encode_prepare_response(&PrepareResponse::Error {
            errno: libc::EIO,
            message: "x".repeat(64 * 1024),
        })
        .is_err()
    );
    assert!(
        encode_prepare_response(&PrepareResponse::Error {
            errno: 0,
            message: "invalid".to_string(),
        })
        .is_err()
    );
}

#[tokio::test]
async fn execution_controller_rejects_an_invalid_token() {
    let root = TestDirectory::new();
    let directory = root.cache();
    let controller = ExecutionController::start(directory.clone()).await.unwrap();
    let mut stream = TcpStream::connect(controller.runtime().control())
        .await
        .unwrap();
    stream
        .write_all(&encode_prepare_request("wrong-token", Path::new("/bin/sh")).unwrap())
        .await
        .unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    let mut response = vec![0_u8; frame_length(prefix).unwrap()];
    stream.read_exact(&mut response).await.unwrap();

    assert_eq!(
        decode_prepare_response(&response).unwrap(),
        PrepareResponse::Error {
            errno: libc::EACCES,
            message: "invalid execution token".to_string(),
        }
    );
    controller.shutdown().await.unwrap();
    assert!(directory.join(".lock").is_file());
}

#[tokio::test]
async fn execution_controller_prepares_and_reuses_the_root_executable() {
    let root = TestDirectory::new();
    let directory = root.cache();
    let controller = ExecutionController::start(directory.clone()).await.unwrap();

    let prepared = controller.prepare(PathBuf::from("/bin/sh")).await.unwrap();

    assert!(prepared.starts_with(&directory));
    assert!(prepared.is_file());
    controller.shutdown().await.unwrap();
    assert!(prepared.is_file());

    let controller = ExecutionController::start(directory).await.unwrap();
    let reused = controller.prepare(PathBuf::from("/bin/sh")).await.unwrap();
    assert_eq!(reused, prepared);
    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn execution_controller_returns_preparation_errors_to_the_hook() {
    let root = TestDirectory::new();
    let controller = ExecutionController::start(root.cache()).await.unwrap();
    let mut stream = TcpStream::connect(controller.runtime().control())
        .await
        .unwrap();
    stream
        .write_all(
            &encode_prepare_request(
                controller.runtime().token(),
                Path::new("/missing/agora-executable"),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    let mut response = vec![0_u8; frame_length(prefix).unwrap()];
    stream.read_exact(&mut response).await.unwrap();

    let PrepareResponse::Error { errno, message } = decode_prepare_response(&response).unwrap()
    else {
        panic!("missing executable must not be prepared");
    };
    assert_eq!(errno, libc::ENOENT);
    assert!(message.contains("failed to resolve executable"));
    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn execution_controller_reports_a_malformed_hook_request() {
    let root = TestDirectory::new();
    let mut controller = ExecutionController::start(root.cache()).await.unwrap();
    let mut stream = TcpStream::connect(controller.runtime().control())
        .await
        .unwrap();
    stream.write_all(&0_u32.to_be_bytes()).await.unwrap();

    let error = controller.wait_failure().await;

    assert!(error.to_string().contains("execution controller failed"));
    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn execution_controller_reports_clean_stops_and_aborted_tasks() {
    let root = TestDirectory::new();
    let mut stopped = ExecutionController::start(root.cache()).await.unwrap();
    stopped.stop_server_for_test();
    assert!(
        stopped
            .wait_failure()
            .await
            .to_string()
            .contains("stopped unexpectedly")
    );
    assert!(
        stopped
            .wait_failure()
            .await
            .to_string()
            .contains("no active task")
    );
    stopped.shutdown().await.unwrap();

    let mut aborted = ExecutionController::start(root.0.join("aborted-cache"))
        .await
        .unwrap();
    aborted.abort_tasks_for_test();
    assert!(
        aborted
            .wait_failure()
            .await
            .to_string()
            .contains("execution task failed")
    );
    aborted.shutdown().await.unwrap();
}

#[tokio::test]
async fn execution_controller_shutdown_reports_task_failures() {
    let root = TestDirectory::new();
    let mut controller = ExecutionController::start(root.cache()).await.unwrap();
    controller.abort_server_for_test();

    assert!(
        controller
            .shutdown()
            .await
            .unwrap_err()
            .to_string()
            .contains("injected execution controller failure")
    );
}

#[tokio::test]
async fn dropping_the_execution_controller_retains_its_cache_directory() {
    let root = TestDirectory::new();
    let directory = root.cache();
    let controller = ExecutionController::start(directory.clone()).await.unwrap();
    assert!(directory.is_dir());

    drop(controller);

    assert!(directory.is_dir());
}
