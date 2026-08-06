use super::Broker;
use crate::nfs::protocol::{RemotePath, Request, Response};
use crate::nfs::testing::MemoryStorage;
use std::io::{Read, Write};

fn path(value: &str) -> RemotePath {
    RemotePath::new(0, value).unwrap()
}

fn open_handle(response: &Response) -> String {
    let Response::Open { handle, .. } = response else {
        panic!("expected open response, got {response:?}");
    };
    handle.clone()
}

#[tokio::test]
async fn broker_opens_remote_content_through_an_unlinked_descriptor() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "notes.txt", b"remote contents");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();

    let reply = broker
        .handle(Request::Open {
            path: path("notes.txt"),
            flags: libc::O_RDONLY,
            mode: 0,
        })
        .await;

    let handle = open_handle(&reply.response);
    let mut file = std::fs::File::from(reply.descriptor.unwrap());
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    assert_eq!(data, "remote contents");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    assert_eq!(
        broker.handle(Request::Close { handle }).await.response,
        Response::Success
    );
}

#[tokio::test]
async fn broker_writes_on_sync_and_last_close_with_posix_open_flags() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();
    let mut reply = broker
        .handle(Request::Open {
            path: path("created.txt"),
            flags: libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            mode: 0o640,
        })
        .await;
    let handle = open_handle(&reply.response);
    let mut file = std::fs::File::from(reply.descriptor.take().unwrap());
    file.write_all(b"first").unwrap();
    file.sync_all().unwrap();

    assert_eq!(
        broker
            .handle(Request::Sync {
                handle: handle.clone()
            })
            .await
            .response,
        Response::Success
    );
    assert_eq!(storage.data(0, "created.txt").unwrap(), b"first");
    file.write_all(b" second").unwrap();
    drop(file);
    assert_eq!(
        broker.handle(Request::Close { handle }).await.response,
        Response::Success
    );
    assert_eq!(storage.data(0, "created.txt").unwrap(), b"first second");

    let exclusive = broker
        .handle(Request::Open {
            path: path("created.txt"),
            flags: libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            mode: 0o600,
        })
        .await;
    assert!(matches!(
        exclusive.response,
        Response::Error {
            errno: libc::EEXIST,
            ..
        }
    ));
}

#[tokio::test]
async fn broker_refuses_to_overwrite_a_remotely_changed_file() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "shared.txt", b"original");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();
    let mut reply = broker
        .handle(Request::Open {
            path: path("shared.txt"),
            flags: libc::O_RDWR | libc::O_TRUNC,
            mode: 0,
        })
        .await;
    let handle = open_handle(&reply.response);
    let mut file = std::fs::File::from(reply.descriptor.take().unwrap());
    file.write_all(b"sandbox change").unwrap();
    file.sync_all().unwrap();
    storage.replace(0, "shared.txt", b"outside change");

    let response = broker.handle(Request::Sync { handle }).await.response;

    assert!(matches!(
        response,
        Response::Error {
            errno: libc::ESTALE,
            ..
        }
    ));
    assert_eq!(storage.data(0, "shared.txt").unwrap(), b"outside change");
}

#[tokio::test(flavor = "current_thread")]
async fn broker_serializes_version_check_and_writeback_per_root() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "shared.txt", b"0");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();

    let mut first = broker
        .handle(Request::Open {
            path: path("shared.txt"),
            flags: libc::O_RDWR,
            mode: 0,
        })
        .await;
    let first_handle = open_handle(&first.response);
    let mut first_file = std::fs::File::from(first.descriptor.take().unwrap());
    first_file.write_all(b"1").unwrap();

    let mut second = broker
        .handle(Request::Open {
            path: path("shared.txt"),
            flags: libc::O_RDWR,
            mode: 0,
        })
        .await;
    let second_handle = open_handle(&second.response);
    let mut second_file = std::fs::File::from(second.descriptor.take().unwrap());
    second_file.write_all(b"2").unwrap();
    storage.yield_operations();

    let (first, second) = tokio::join!(
        broker.handle(Request::Sync {
            handle: first_handle,
        }),
        broker.handle(Request::Sync {
            handle: second_handle,
        }),
    );

    let responses = [first.response, second.response];
    assert_eq!(
        responses
            .iter()
            .filter(|response| **response == Response::Success)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| matches!(
                response,
                Response::Error {
                    errno: libc::ESTALE,
                    ..
                }
            ))
            .count(),
        1
    );
}

#[tokio::test]
async fn broker_does_not_publish_an_unchanged_writable_snapshot() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "shared.txt", b"original");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();
    let reply = broker
        .handle(Request::Open {
            path: path("shared.txt"),
            flags: libc::O_RDWR,
            mode: 0,
        })
        .await;
    let handle = open_handle(&reply.response);
    let file = std::fs::File::from(reply.descriptor.unwrap());
    storage.replace(0, "shared.txt", b"outside change");

    let response = broker.handle(Request::Close { handle }).await.response;

    assert_eq!(response, Response::Success);
    assert_eq!(storage.data(0, "shared.txt").unwrap(), b"outside change");
    drop(file);
}

#[tokio::test]
async fn broker_publishes_an_empty_file_created_with_read_only_access() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();
    let reply = broker
        .handle(Request::Open {
            path: path("empty.txt"),
            flags: libc::O_RDONLY | libc::O_CREAT,
            mode: 0o600,
        })
        .await;
    let handle = open_handle(&reply.response);
    drop(reply.descriptor.unwrap());

    let response = broker.handle(Request::Close { handle }).await.response;

    assert_eq!(response, Response::Success);
    assert_eq!(storage.data(0, "empty.txt"), Some(Vec::new()));
}

#[tokio::test]
async fn broker_abort_discards_a_staged_create_without_publishing_it() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();
    let reply = broker
        .handle(Request::Open {
            path: path("aborted.txt"),
            flags: libc::O_WRONLY | libc::O_CREAT,
            mode: 0o600,
        })
        .await;
    let handle = open_handle(&reply.response);
    drop(reply.descriptor.unwrap());

    assert_eq!(
        broker.handle(Request::Abort { handle }).await.response,
        Response::Success
    );
    assert!(!storage.exists(0, "aborted.txt"));
}

#[tokio::test]
async fn broker_handles_directory_and_namespace_operations() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_directory(0, "");
    storage.insert_directory(0, "docs");
    storage.insert_file(0, "docs/a.txt", b"a");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();

    let list = broker.handle(Request::List { path: path("docs") }).await;
    let Response::List { entries, anchor } = list.response else {
        panic!("expected list response");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "a.txt");
    assert!(!anchor.contains("docs"));
    assert!(root.path().join(anchor).is_dir());
    assert_eq!(
        broker
            .handle(Request::Rename {
                from: path("docs/a.txt"),
                to: path("docs/b.txt"),
            })
            .await
            .response,
        Response::Success
    );
    assert_eq!(
        broker
            .handle(Request::Remove {
                path: path("docs/b.txt"),
                directory: false,
            })
            .await
            .response,
        Response::Success
    );
    assert_eq!(
        broker
            .handle(Request::CreateDirectory {
                path: path("empty"),
                mode: 0o755,
            })
            .await
            .response,
        Response::Success
    );
    assert_eq!(
        broker
            .handle(Request::Remove {
                path: path("empty"),
                directory: true,
            })
            .await
            .response,
        Response::Success
    );
}

#[tokio::test]
async fn broker_protects_the_configured_remote_root_from_namespace_mutation() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_directory(0, "");
    storage.insert_file(0, "file.txt", b"file");
    let broker = Broker::new(storage, root.path()).unwrap();

    assert!(matches!(
        broker
            .handle(Request::Remove {
                path: path(""),
                directory: true,
            })
            .await
            .response,
        Response::Error {
            errno: libc::EACCES,
            ..
        }
    ));

    for request in [
        Request::Rename {
            from: path(""),
            to: path("moved"),
        },
        Request::Rename {
            from: path("file.txt"),
            to: path(""),
        },
    ] {
        assert!(matches!(
            broker.handle(request).await.response,
            Response::Error {
                errno: libc::EBUSY,
                ..
            }
        ));
    }
    assert!(matches!(
        broker
            .handle(Request::CreateDirectory {
                path: path(""),
                mode: 0o755,
            })
            .await
            .response,
        Response::Error {
            errno: libc::EEXIST,
            ..
        }
    ));
}

#[tokio::test]
async fn broker_retargets_open_descendants_when_a_directory_is_renamed() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_directory(0, "");
    storage.insert_directory(0, "docs");
    storage.insert_file(0, "docs/open.txt", b"old");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();
    let reply = broker
        .handle(Request::Open {
            path: path("docs/open.txt"),
            flags: libc::O_RDWR | libc::O_TRUNC,
            mode: 0,
        })
        .await;
    let handle = open_handle(&reply.response);
    let mut file = std::fs::File::from(reply.descriptor.unwrap());
    file.write_all(b"new").unwrap();

    assert_eq!(
        broker
            .handle(Request::Rename {
                from: path("docs"),
                to: path("renamed"),
            })
            .await
            .response,
        Response::Success
    );
    assert_eq!(
        broker.handle(Request::Close { handle }).await.response,
        Response::Success
    );
    assert_eq!(storage.data(0, "renamed/open.txt"), Some(b"new".to_vec()));
    assert!(!storage.exists(0, "docs/open.txt"));
}

#[tokio::test]
async fn broker_discards_an_open_snapshot_after_the_path_is_removed() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "open.txt", b"old");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();
    let reply = broker
        .handle(Request::Open {
            path: path("open.txt"),
            flags: libc::O_RDWR | libc::O_TRUNC,
            mode: 0,
        })
        .await;
    let handle = open_handle(&reply.response);
    let mut file = std::fs::File::from(reply.descriptor.unwrap());
    file.write_all(b"unlinked data").unwrap();

    assert_eq!(
        broker
            .handle(Request::Remove {
                path: path("open.txt"),
                directory: false,
            })
            .await
            .response,
        Response::Success
    );
    assert_eq!(
        broker.handle(Request::Close { handle }).await.response,
        Response::Success
    );
    assert!(!storage.exists(0, "open.txt"));
}
