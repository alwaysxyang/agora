use super::*;
use crate::filesystem::broker::LocalClient;
use crate::filesystem::broker::protocol::{
    BackingPath, ByteRange, Request, RequestEnvelope, Response, ResponseEnvelope,
};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

fn cipher() -> FileCipher {
    FileCipher::derive(b"controller-key", b"0123456789abcdef").unwrap()
}

fn idle_controller(root: &Path, tasks: JoinSet<Result<()>>) -> LocalController {
    let (shutdown, _receiver) = watch::channel(false);
    LocalController {
        runtime: LocalRuntime {
            socket: root.join("unused.sock"),
            token: "token".to_string(),
        },
        broker: Arc::new(LocalBroker::new(root, cipher()).unwrap()),
        shutdown,
        tasks,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_serves_the_complete_local_client_lifecycle() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("fs");
    let runtime = directory.path().join("runtime");
    std::fs::create_dir(&root).unwrap();
    let cipher = cipher();
    let backing = root.join("content");
    let mut source = tempfile::tempfile().unwrap();
    source.write_all(b"before").unwrap();
    cipher.encrypt(&mut source, &backing).unwrap();
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(b"before").unwrap();

    let controller = LocalController::start(&root, cipher.clone(), &runtime)
        .await
        .unwrap();
    assert_eq!(
        controller.runtime().socket(),
        runtime.join("local-filesystem.sock")
    );
    assert_eq!(controller.runtime().token().len(), 32);
    let client = LocalClient::new(controller.runtime().socket(), controller.runtime().token());
    let descriptor = plaintext.as_raw_fd();
    let handle = tokio::task::spawn_blocking(move || {
        let opened = client.open(&backing, descriptor, true).unwrap();
        plaintext.write_all_at(b"after!", 0).unwrap();
        client
            .potentially_dirty(&opened.handle, ByteRange::new(0, 6).unwrap())
            .unwrap();
        client
            .sync(&opened.handle, vec![ByteRange::new(0, 3).unwrap()], false)
            .unwrap();
        client.retain(vec![opened.handle.clone()]).unwrap();
        client.close(&opened.handle).unwrap();
        client.close(&opened.handle).unwrap();
        opened.handle
    })
    .await
    .unwrap();
    assert_eq!(handle.len(), 32);
    controller.shutdown().await.unwrap();

    let mut restored = tempfile::tempfile().unwrap();
    cipher
        .decrypt(&root.join("content"), &mut restored)
        .unwrap();
    restored.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = String::new();
    restored.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "after!");
    assert!(!runtime.join("local-filesystem.sock").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controller_rejects_wrong_tokens_versions_and_unexpected_descriptors() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("fs");
    std::fs::create_dir(&root).unwrap();
    let controller = LocalController::start(&root, cipher(), &directory.path().join("runtime"))
        .await
        .unwrap();

    let wrong = LocalClient::new(controller.runtime().socket(), "wrong");
    let error = tokio::task::spawn_blocking(move || wrong.close("missing"))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.errno(), libc::EACCES);

    let socket = controller.runtime().socket().to_path_buf();
    let token = controller.runtime().token().to_string();
    let response = tokio::task::spawn_blocking(move || {
        let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
        ipc::send(
            &mut stream,
            &RequestEnvelope {
                version: PROTOCOL_VERSION + 1,
                token,
                request_id: "old-version".to_string(),
                request: Request::Close {
                    handle: "missing".to_string(),
                },
            },
            Some(tempfile::tempfile().unwrap().as_raw_fd()),
        )
        .unwrap();
        ipc::receive::<ResponseEnvelope>(&mut stream).unwrap().0
    })
    .await
    .unwrap();
    assert!(matches!(
        response.response,
        Response::Error {
            errno: libc::EPROTO,
            ..
        }
    ));
    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn controller_failure_reporting_distinguishes_task_outcomes() {
    let root = tempfile::tempdir().unwrap();

    let mut successful = JoinSet::new();
    successful.spawn(async { Ok(()) });
    let mut controller = idle_controller(root.path(), successful);
    assert!(
        controller
            .wait_failure()
            .await
            .to_string()
            .contains("stopped unexpectedly")
    );

    let mut failed = JoinSet::new();
    failed.spawn(async { anyhow::bail!("server error") });
    let mut controller = idle_controller(root.path(), failed);
    assert!(
        format!("{:#}", controller.wait_failure().await).contains("local filesystem broker failed")
    );

    let mut panicked = JoinSet::new();
    panicked.spawn(async {
        panic!("server panic");
        #[allow(unreachable_code)]
        Ok(())
    });
    let mut controller = idle_controller(root.path(), panicked);
    assert!(
        format!("{:#}", controller.wait_failure().await)
            .contains("local filesystem broker task failed")
    );

    let mut controller = idle_controller(root.path(), JoinSet::new());
    assert!(
        controller
            .wait_failure()
            .await
            .to_string()
            .contains("no active task")
    );
}

#[tokio::test]
async fn shutdown_reports_service_errors_and_drop_removes_the_socket() {
    let root = tempfile::tempdir().unwrap();
    let mut tasks = JoinSet::new();
    tasks.spawn(async { anyhow::bail!("shutdown failure") });
    let controller = idle_controller(root.path(), tasks);
    assert!(
        controller
            .shutdown()
            .await
            .unwrap_err()
            .to_string()
            .contains("shutdown failure")
    );

    let runtime = tempfile::tempdir().unwrap();
    let controller = LocalController::start(root.path(), cipher(), runtime.path())
        .await
        .unwrap();
    let socket = controller.runtime().socket().to_path_buf();
    assert!(socket.exists());
    drop(controller);
    assert!(!socket.exists());
}

#[tokio::test]
async fn startup_errors_and_constant_time_token_checks_are_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let error = match LocalController::start(
        &directory.path().join("missing-root"),
        cipher(),
        &directory.path().join("runtime"),
    )
    .await
    {
        Ok(_) => panic!("unexpectedly started with a missing root"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("No such file"));

    assert!(constant_time_equal(b"same", b"same"));
    assert!(!constant_time_equal(b"same", b"diff"));
    assert!(!constant_time_equal(b"short", b"longer"));

    let request = Request::Open {
        path: BackingPath::from_path(Path::new("/tmp/example")),
        writable: false,
    };
    assert!(matches!(request, Request::Open { .. }));
}
