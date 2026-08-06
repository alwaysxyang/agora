use super::{
    RemoteConnectionStatus, RemoteController, RemoteControllerEvent, configure_server_stream,
};
use crate::nfs::client::RemoteClient;
use crate::nfs::protocol::{RemotePath, Request, Response};
use crate::nfs::testing::MemoryStorage;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn controller_bounds_blocking_request_and_response_io() {
    let (server, _client) = std::os::unix::net::UnixStream::pair().unwrap();
    let read = Duration::from_millis(25);
    let write = Duration::from_millis(50);

    configure_server_stream(&server, read, write).unwrap();

    assert_eq!(server.read_timeout().unwrap(), Some(read));
    assert_eq!(server.write_timeout().unwrap(), Some(write));
}

#[tokio::test]
async fn controller_probes_remote_roots_without_blocking_startup() {
    let runtime = tempfile::tempdir().unwrap();
    let storage = Arc::new(MemoryStorage::default());
    storage.block_connections();
    storage.fail_connection(1, libc::EACCES, "credentials rejected");

    let mut controller = tokio::time::timeout(
        Duration::from_millis(100),
        RemoteController::start_with_storage_and_connection_probes(
            Arc::clone(&storage),
            runtime.path(),
            2,
        ),
    )
    .await
    .expect("controller startup must not await connection probes")
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), controller.wait_event())
            .await
            .is_err(),
        "blocked connection probes must still be running in the background"
    );

    storage.release_connections();
    let mut statuses = Vec::new();
    for _ in 0..2 {
        let event = tokio::time::timeout(Duration::from_secs(1), controller.wait_event())
            .await
            .unwrap();
        let RemoteControllerEvent::Connection(status) = event else {
            panic!("connection failure must not stop the controller");
        };
        statuses.push(status);
    }
    statuses.sort_by_key(RemoteConnectionStatus::root);
    assert_eq!(
        statuses,
        vec![
            RemoteConnectionStatus::Connected { root: 0 },
            RemoteConnectionStatus::Unavailable {
                root: 1,
                errno: libc::EACCES,
            },
        ]
    );
    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn controller_authenticates_requests_and_transfers_open_descriptors() {
    let runtime = tempfile::tempdir().unwrap();
    let storage = Arc::new(MemoryStorage::default());
    storage.insert_file(0, "file.txt", b"through broker");
    let controller = RemoteController::start_with_storage(Arc::clone(&storage), runtime.path())
        .await
        .unwrap();
    let client = RemoteClient::new(controller.runtime().socket(), controller.runtime().token());

    let reply = tokio::task::spawn_blocking(move || {
        client.request(Request::Open {
            path: RemotePath::new(0, "file.txt").unwrap(),
            flags: libc::O_RDONLY,
            mode: 0,
        })
    })
    .await
    .unwrap()
    .unwrap();

    assert!(matches!(reply.response, Response::Open { .. }));
    let mut file = std::fs::File::from(reply.descriptor.unwrap());
    let mut contents = String::new();
    std::io::Read::read_to_string(&mut file, &mut contents).unwrap();
    assert_eq!(contents, "through broker");
    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn controller_rejects_an_invalid_token_before_storage_access() {
    let runtime = tempfile::tempdir().unwrap();
    let storage = Arc::new(MemoryStorage::default());
    storage.insert_file(0, "file.txt", b"secret");
    let controller = RemoteController::start_with_storage(storage, runtime.path())
        .await
        .unwrap();
    let client = RemoteClient::new(controller.runtime().socket(), "wrong-token");

    let error = tokio::task::spawn_blocking(move || {
        client.request(Request::Stat {
            path: RemotePath::new(0, "file.txt").unwrap(),
        })
    })
    .await
    .unwrap()
    .unwrap_err();

    assert_eq!(error.errno(), libc::EACCES);
    controller.shutdown().await.unwrap();
}

#[tokio::test]
async fn controller_reports_an_injected_service_failure() {
    let runtime = tempfile::tempdir().unwrap();
    let storage = Arc::new(MemoryStorage::default());
    let mut controller = RemoteController::start_with_storage(storage, runtime.path())
        .await
        .unwrap();

    controller.abort_server_for_test();

    let error = controller.wait_failure().await;
    assert!(format!("{error:#}").contains("injected remote filesystem failure"));
}
