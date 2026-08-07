use super::*;
use crate::nfs::backend::RemoteStorage;
use crate::nfs::protocol::{RemotePath, Request, RequestId, Response};
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

fn request_id(value: u128) -> RequestId {
    RequestId::new(format!("{value:032x}")).unwrap()
}

fn assert_errno(response: Response, errno: libc::c_int) {
    assert!(
        matches!(response, Response::Error { errno: actual, .. } if actual == errno),
        "unexpected response: {response:?}"
    );
}

#[tokio::test]
async fn broker_replays_duplicate_open_without_allocating_another_handle() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "notes.txt", b"remote contents");
    let broker = Broker::new(storage, root.path()).unwrap();
    let request = Request::Open {
        path: path("notes.txt"),
        flags: libc::O_RDONLY,
        mode: 0,
    };

    let first = broker.handle_request(request_id(1), request.clone()).await;
    let replay = broker.handle_request(request_id(1), request).await;

    assert_eq!(open_handle(&first.response), open_handle(&replay.response));
    assert!(first.descriptor.is_some());
    assert!(replay.descriptor.is_some());
    assert_eq!(broker.handle_count_for_test().await, 1);
}

#[tokio::test]
async fn broker_treats_close_as_idempotent_across_request_ids() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "notes.txt", b"remote contents");
    let broker = Broker::new(storage, root.path()).unwrap();
    let opened = broker
        .handle_request(
            request_id(2),
            Request::Open {
                path: path("notes.txt"),
                flags: libc::O_RDONLY,
                mode: 0,
            },
        )
        .await;
    let handle = open_handle(&opened.response);

    assert_eq!(
        broker
            .handle_request(
                request_id(3),
                Request::Close {
                    handle: handle.clone(),
                },
            )
            .await
            .response,
        Response::Success
    );
    assert_eq!(
        broker
            .handle_request(request_id(4), Request::Close { handle })
            .await
            .response,
        Response::Success
    );
}

#[tokio::test]
async fn broker_rejects_reusing_a_request_id_for_a_different_operation() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "one.txt", b"one");
    storage.insert_file(0, "two.txt", b"two");
    let broker = Broker::new(storage, root.path()).unwrap();

    let _ = broker
        .handle_request(
            request_id(5),
            Request::Stat {
                path: path("one.txt"),
            },
        )
        .await;
    let response = broker
        .handle_request(
            request_id(5),
            Request::Stat {
                path: path("two.txt"),
            },
        )
        .await
        .response;

    assert!(matches!(
        response,
        Response::Error {
            errno: libc::EPROTO,
            ..
        }
    ));
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

    assert!(matches!(
        broker
            .handle(Request::Sync {
                handle: handle.clone()
            })
            .await
            .response,
        Response::Synced { metadata: Some(_) }
    ));
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

#[tokio::test]
async fn storage_compare_and_write_is_atomic_with_respect_to_its_version() {
    let storage = MemoryStorage::default();
    storage.insert_file(0, "shared.txt", b"original");
    let expected = storage.stat(&path("shared.txt")).await.unwrap();
    storage.replace(0, "shared.txt", b"outside change");

    let error = storage
        .write_if_unchanged(&path("shared.txt"), Some(&expected), b"sandbox change")
        .await
        .unwrap_err();

    assert_eq!(error.errno(), libc::ESTALE);
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
            .filter(|response| matches!(response, Response::Synced { metadata: Some(_) }))
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
async fn broker_rename_replaces_an_existing_file() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "source.txt", b"source");
    storage.insert_file(0, "target.txt", b"target");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();

    let response = broker
        .handle(Request::Rename {
            from: path("source.txt"),
            to: path("target.txt"),
        })
        .await
        .response;

    assert_eq!(response, Response::Success);
    assert!(!storage.exists(0, "source.txt"));
    assert_eq!(storage.data(0, "target.txt"), Some(b"source".to_vec()));
}

#[tokio::test]
async fn replaced_target_handle_cannot_recreate_or_overwrite_the_new_target() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_file(0, "source.txt", b"source");
    storage.insert_file(0, "target.txt", b"target");
    let broker = Broker::new(std::sync::Arc::clone(&storage), root.path()).unwrap();
    let mut opened = broker
        .handle(Request::Open {
            path: path("target.txt"),
            flags: libc::O_RDWR,
            mode: 0,
        })
        .await;
    let handle = open_handle(&opened.response);
    let mut descriptor = std::fs::File::from(opened.descriptor.take().unwrap());
    descriptor.write_all(b"changed target").unwrap();

    assert_eq!(
        broker
            .handle(Request::Rename {
                from: path("source.txt"),
                to: path("target.txt"),
            })
            .await
            .response,
        Response::Success
    );
    assert_eq!(
        broker
            .handle(Request::Sync {
                handle: handle.clone(),
            })
            .await
            .response,
        Response::Synced { metadata: None }
    );
    assert_eq!(
        broker.handle(Request::Close { handle }).await.response,
        Response::Success
    );
    assert_eq!(storage.data(0, "target.txt"), Some(b"source".to_vec()));
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
        broker
            .handle(Request::Sync {
                handle: handle.clone(),
            })
            .await
            .response,
        Response::Synced { metadata: None }
    );
    assert_eq!(
        broker.handle(Request::Close { handle }).await.response,
        Response::Success
    );
    assert!(!storage.exists(0, "open.txt"));
}

#[tokio::test]
async fn broker_validates_open_access_directory_and_sync_semantics() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_directory(0, "");
    storage.insert_directory(0, "docs");
    storage.insert_file(0, "file.txt", b"file");
    let broker = Broker::new(storage, root.path()).unwrap();

    for (flags, errno) in [
        (3, libc::EINVAL),
        (libc::O_RDONLY | libc::O_TRUNC, libc::EINVAL),
    ] {
        assert_errno(
            broker
                .handle(Request::Open {
                    path: path("file.txt"),
                    flags,
                    mode: 0,
                })
                .await
                .response,
            errno,
        );
    }
    assert_errno(
        broker
            .handle(Request::Open {
                path: path("missing.txt"),
                flags: libc::O_RDONLY,
                mode: 0,
            })
            .await
            .response,
        libc::ENOENT,
    );
    assert_errno(
        broker
            .handle(Request::Open {
                path: path("file.txt"),
                flags: libc::O_RDONLY | libc::O_DIRECTORY,
                mode: 0,
            })
            .await
            .response,
        libc::ENOTDIR,
    );
    assert_errno(
        broker
            .handle(Request::Open {
                path: path("missing.txt"),
                flags: libc::O_RDONLY | libc::O_DIRECTORY,
                mode: 0,
            })
            .await
            .response,
        libc::ENOENT,
    );
    assert_errno(
        broker
            .handle(Request::Open {
                path: path("docs"),
                flags: libc::O_WRONLY,
                mode: 0,
            })
            .await
            .response,
        libc::EISDIR,
    );

    let directory = broker
        .handle(Request::Open {
            path: path("docs"),
            flags: libc::O_RDONLY,
            mode: 0,
        })
        .await;
    let handle = open_handle(&directory.response);
    assert!(
        std::fs::File::from(directory.descriptor.unwrap())
            .metadata()
            .unwrap()
            .is_dir()
    );
    assert_eq!(
        broker.handle(Request::Close { handle }).await.response,
        Response::Success
    );

    assert_errno(
        broker
            .handle(Request::Access {
                path: path("file.txt"),
                mode: 8,
            })
            .await
            .response,
        libc::EINVAL,
    );
    assert_errno(
        broker
            .handle(Request::Access {
                path: path("file.txt"),
                mode: libc::X_OK,
            })
            .await
            .response,
        libc::EACCES,
    );
    assert_eq!(
        broker
            .handle(Request::Access {
                path: path("docs"),
                mode: libc::R_OK | libc::X_OK,
            })
            .await
            .response,
        Response::Success
    );
    assert_errno(
        broker
            .handle(Request::Sync {
                handle: "missing".to_string(),
            })
            .await
            .response,
        libc::EBADF,
    );
    assert_errno(
        broker
            .handle(Request::Abort {
                handle: "missing".to_string(),
            })
            .await
            .response,
        libc::EBADF,
    );
    assert_errno(
        broker
            .handle(Request::Close {
                handle: "missing".to_string(),
            })
            .await
            .response,
        libc::EBADF,
    );
}

#[tokio::test]
async fn broker_reclaims_unclaimed_open_and_anchor_resources() {
    let root = tempfile::tempdir().unwrap();
    let storage = std::sync::Arc::new(MemoryStorage::default());
    storage.insert_directory(0, "");
    storage.insert_file(0, "file.txt", b"file");
    let broker = Broker::new(storage, root.path()).unwrap();

    let stat_id = request_id(100);
    let stat = broker
        .handle_request(
            stat_id.clone(),
            Request::Stat {
                path: path("file.txt"),
            },
        )
        .await;
    let Response::Stat { anchor, .. } = stat.response else {
        panic!("expected stat response");
    };
    assert!(root.path().join(&anchor).is_file());
    assert_eq!(
        broker
            .handle(Request::Claim {
                request_id: stat_id.clone(),
            })
            .await
            .response,
        Response::Success
    );
    assert_eq!(
        broker
            .handle(Request::Claim {
                request_id: stat_id,
            })
            .await
            .response,
        Response::Success
    );
    std::fs::remove_file(root.path().join(anchor)).unwrap();

    let anchor_id = request_id(101);
    let listed = broker
        .handle_request(anchor_id.clone(), Request::List { path: path("") })
        .await;
    let Response::List { anchor, .. } = listed.response else {
        panic!("expected list response");
    };
    let open_id = request_id(102);
    let opened = broker
        .handle_request(
            open_id.clone(),
            Request::Open {
                path: path("file.txt"),
                flags: libc::O_RDONLY,
                mode: 0,
            },
        )
        .await;
    let handle = open_handle(&opened.response);
    drop(opened.descriptor);

    let expired = Instant::now() - REQUEST_CACHE_TTL - Duration::from_secs(1);
    let mut requests = broker.requests.lock().await;
    for id in [&anchor_id, &open_id] {
        let CachedRequest::Completed { completed_at, .. } = requests.entries.get_mut(id).unwrap()
        else {
            panic!("request must be completed");
        };
        *completed_at = expired;
    }
    drop(requests);
    broker.expire_requests().await;

    assert!(!root.path().join(anchor).exists());
    assert_eq!(broker.handle_count_for_test().await, 0);
    assert!(broker.closed_handles.lock().await.contains(&handle));
    assert_errno(
        broker
            .reply_for_response(Response::Open {
                handle,
                metadata: empty_file_metadata(),
            })
            .await
            .response,
        libc::EBADF,
    );
    assert_eq!(
        broker.reply_for_response(Response::Success).await.response,
        Response::Success
    );
    assert_errno(
        broker
            .handle(Request::Claim {
                request_id: request_id(999),
            })
            .await
            .response,
        libc::EPROTO,
    );
}

#[tokio::test]
async fn request_cache_waiters_capacity_and_tombstones_are_bounded() {
    let mut cache = RequestCache::default();
    let id = request_id(200);
    let request = Request::Access {
        path: path("file.txt"),
        mode: libc::R_OK,
    };
    assert!(matches!(
        cache.begin(id.clone(), request.clone()),
        CacheDecision::Execute
    ));
    let CacheDecision::Wait(waiter) = cache.begin(id.clone(), request.clone()) else {
        panic!("duplicate pending request must wait");
    };
    assert!(cache.complete(id.clone(), Response::Success).is_empty());
    assert_eq!(waiter.await.unwrap(), Response::Success);
    assert!(matches!(
        cache.begin(id.clone(), request.clone()),
        CacheDecision::Replay(Response::Success)
    ));
    assert!(matches!(
        cache.begin(
            id,
            Request::Access {
                path: path("different"),
                mode: libc::R_OK,
            }
        ),
        CacheDecision::Reject
    ));
    assert!(
        cache
            .complete(request_id(201), Response::Success)
            .is_empty()
    );
    assert!(!cache.claim(&request_id(201)));
    assert!(!cache.claim(&request_id(200)));

    for value in 0..=REQUEST_CACHE_CAPACITY {
        cache.entries.insert(
            request_id(10_000 + value as u128),
            CachedRequest::Completed {
                request: request.clone(),
                response: Response::Success,
                completed_at: Instant::now() + Duration::from_nanos(value as u64),
                claimed: true,
            },
        );
    }
    let _ = cache.prune(Instant::now());
    assert!(cache.entries.len() <= REQUEST_CACHE_CAPACITY + 1);

    let mut tombstones = HandleTombstones::default();
    for value in 0..=CLOSED_HANDLE_CAPACITY {
        tombstones.insert(format!("handle-{value}"));
    }
    tombstones.insert("handle-1".to_string());
    assert!(!tombstones.contains("handle-0"));
    assert!(tombstones.contains(&format!("handle-{CLOSED_HANDLE_CAPACITY}")));
}

#[tokio::test]
async fn broker_cleanup_and_path_helpers_cover_file_directory_and_cross_root_cases() {
    let root = tempfile::tempdir().unwrap();
    let broker = Broker::new(std::sync::Arc::new(MemoryStorage::default()), root.path()).unwrap();
    std::fs::write(root.path().join("file-anchor"), b"").unwrap();
    std::fs::create_dir(root.path().join("dir-anchor")).unwrap();
    std::fs::create_dir(root.path().join("nonempty-anchor")).unwrap();
    std::fs::write(root.path().join("nonempty-anchor/child"), b"").unwrap();
    broker
        .discard_abandoned_resources(vec![
            AbandonedResource::Anchor("file-anchor".to_string()),
            AbandonedResource::Anchor("dir-anchor".to_string()),
            AbandonedResource::Anchor("nonempty-anchor".to_string()),
            AbandonedResource::Anchor("missing-anchor".to_string()),
            AbandonedResource::Handle("missing-handle".to_string()),
        ])
        .await;
    assert!(!root.path().join("file-anchor").exists());
    assert!(!root.path().join("dir-anchor").exists());
    assert!(root.path().join("nonempty-anchor/child").is_file());
    std::fs::remove_dir_all(root.path().join("nonempty-anchor")).unwrap();

    let source = RemotePath::new(0, "source").unwrap();
    let child = RemotePath::new(0, "source/child").unwrap();
    let sibling = RemotePath::new(0, "source-other").unwrap();
    let target = RemotePath::new(0, "target").unwrap();
    assert_eq!(
        retarget_path(&source, &source, &target),
        Some(target.clone())
    );
    assert_eq!(
        retarget_path(&child, &source, &target),
        Some(RemotePath::new(0, "target/child").unwrap())
    );
    assert_eq!(retarget_path(&sibling, &source, &target), None);
    assert_eq!(
        retarget_path(&RemotePath::new(1, "source").unwrap(), &source, &target,),
        None
    );
    assert!(path_is_at_or_below(&child, &source));
    assert!(!path_is_at_or_below(&sibling, &source));
    assert!(!path_is_at_or_below(
        &RemotePath::new(1, "source").unwrap(),
        &source,
    ));

    assert_errno(
        broker
            .handle(Request::Rename {
                from: RemotePath::new(0, "source").unwrap(),
                to: RemotePath::new(1, "target").unwrap(),
            })
            .await
            .response,
        libc::EXDEV,
    );
    let error = storage_io("context", std::io::Error::other("failure"));
    assert_eq!(error.errno(), libc::EIO);
}

#[test]
fn close_on_exec_reports_an_invalid_descriptor() {
    use std::os::fd::AsRawFd as _;

    let file = std::mem::ManuallyDrop::new(std::fs::File::open("/dev/null").unwrap());
    let descriptor = file.as_raw_fd();
    assert_eq!(unsafe { libc::close(descriptor) }, 0);

    let error = set_close_on_exec(&file).unwrap_err();

    assert_eq!(error.errno(), libc::EBADF);
    assert!(
        error
            .to_string()
            .contains("protect anonymous remote descriptor")
    );
}
