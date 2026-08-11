use super::*;
use crate::audit::protocol::{decode_response, encode_ping_request, encode_request};
use crate::callback::{Decision, FileAccessMode, FileContext, FileOpenMode, ProcessContext};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn controller() -> AuditController {
    AuditController::start(
        "sandbox".to_string(),
        "run".to_string(),
        |_| std::future::ready(Decision::Allow),
        Duration::from_secs(1),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn audit_server_drops_connections_above_its_concurrency_limit() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = Arc::new(AuditState {
        token: "token".to_string(),
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        callback: |_| std::future::ready(Decision::Allow),
        callback_timeout: Duration::from_secs(1),
        requests: Mutex::new(AuditRequestCache::default()),
    });
    let server = AuditServer::new(listener, state);
    let permits = (0..AUDIT_MAX_CONNECTIONS)
        .map(|_| Arc::clone(&server.connections).try_acquire_owned().unwrap())
        .collect::<Vec<_>>();
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(server.run(receiver));

    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    drop(permits);
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn audit_controller_reports_empty_successful_and_panicked_task_sets() {
    let mut empty = controller().await;
    empty.tasks.shutdown().await;
    assert!(
        empty
            .wait_failure()
            .await
            .to_string()
            .contains("no active task")
    );

    let mut stopped = controller().await;
    stopped.tasks.shutdown().await;
    stopped.tasks.spawn(async { Ok(()) });
    assert!(
        stopped
            .wait_failure()
            .await
            .to_string()
            .contains("stopped unexpectedly")
    );

    let mut panicked = controller().await;
    panicked.tasks.shutdown().await;
    panicked.tasks.spawn(async {
        panic!("injected audit task panic");
        #[allow(unreachable_code)]
        Ok(())
    });
    assert!(
        panicked
            .wait_failure()
            .await
            .to_string()
            .contains("audit task failed")
    );

    let mut shutdown = controller().await;
    shutdown.tasks.shutdown().await;
    shutdown.tasks.spawn(async {
        panic!("injected audit shutdown panic");
        #[allow(unreachable_code)]
        Ok(())
    });
    assert!(shutdown.shutdown().await.is_err());

    let mut failed = controller().await;
    failed.tasks.shutdown().await;
    failed.tasks.spawn(async {
        anyhow::bail!("injected audit task failure");
    });
    assert!(
        failed
            .wait_failure()
            .await
            .to_string()
            .contains("audit controller failed")
    );

    let mut failed_shutdown = controller().await;
    failed_shutdown.tasks.shutdown().await;
    failed_shutdown.tasks.spawn(async {
        anyhow::bail!("injected audit shutdown failure");
    });
    assert!(failed_shutdown.shutdown().await.is_err());
}

#[tokio::test]
async fn audit_server_times_out_idle_established_connections() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let state = Arc::new(AuditState {
        token: "token".to_string(),
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        callback: |_| std::future::ready(Decision::Allow),
        callback_timeout: Duration::from_secs(1),
        requests: Mutex::new(AuditRequestCache::default()),
    });
    let task = tokio::spawn(AuditServer::handle_with_timeouts(
        server,
        state,
        Duration::from_secs(1),
        Duration::from_millis(20),
    ));
    let event = AuditEventRequest::File {
        trace_id: "trace".to_string(),
        process: ProcessContext {
            pid: 1,
            ppid: 0,
            executable: "/bin/tool".to_string(),
        },
        operation: FileOperation::Open,
        file: FileContext {
            path: "/tmp/file".to_string(),
            mode: FileOpenMode {
                access: FileAccessMode::Read,
                create: false,
                truncate: false,
                append: false,
                exclusive: false,
            },
        },
    };
    client
        .write_all(&encode_request("token", event).unwrap())
        .await
        .unwrap();
    let mut prefix = [0_u8; 4];
    client.read_exact(&mut prefix).await.unwrap();
    let mut response = vec![0_u8; frame_length(prefix).unwrap()];
    client.read_exact(&mut response).await.unwrap();

    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("connection timed out"));
}

#[tokio::test]
async fn audit_server_keeps_an_authenticated_control_stream() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let state = Arc::new(AuditState {
        token: "token".to_string(),
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        callback: |_| std::future::ready(Decision::Allow),
        callback_timeout: Duration::from_secs(1),
        requests: Mutex::new(AuditRequestCache::default()),
    });
    let task = tokio::spawn(AuditServer::handle_with_timeouts(
        server,
        state,
        Duration::from_secs(1),
        Duration::from_millis(20),
    ));
    client
        .write_all(&encode_ping_request("token").unwrap())
        .await
        .unwrap();
    let mut prefix = [0_u8; 4];
    client.read_exact(&mut prefix).await.unwrap();
    let mut response = vec![0_u8; frame_length(prefix).unwrap()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(decode_response(&response).unwrap(), AuditResponse::Accepted);

    tokio::time::sleep(Duration::from_millis(50)).await;
    client
        .write_all(
            &encode_request(
                "token",
                AuditEventRequest::File {
                    trace_id: "trace".to_string(),
                    process: ProcessContext {
                        pid: 1,
                        ppid: 0,
                        executable: "/bin/tool".to_string(),
                    },
                    operation: FileOperation::Open,
                    file: FileContext {
                        path: "/tmp/file".to_string(),
                        mode: FileOpenMode {
                            access: FileAccessMode::Read,
                            create: false,
                            truncate: false,
                            append: false,
                            exclusive: false,
                        },
                    },
                },
            )
            .unwrap(),
        )
        .await
        .unwrap();
    client.read_exact(&mut prefix).await.unwrap();
    let mut response = vec![0_u8; frame_length(prefix).unwrap()];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(decode_response(&response).unwrap(), AuditResponse::Accepted);

    drop(client);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn duplicate_audit_request_ids_publish_one_logical_event() {
    let published = Arc::new(AtomicUsize::new(0));
    let callback_count = Arc::clone(&published);
    let state = Arc::new(AuditState {
        token: "token".to_string(),
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        callback: move |_| {
            callback_count.fetch_add(1, Ordering::Relaxed);
            std::future::ready(Decision::Allow)
        },
        callback_timeout: Duration::from_secs(1),
        requests: Mutex::new(AuditRequestCache::default()),
    });
    let event = AuditEventRequest::File {
        trace_id: "trace".to_string(),
        process: ProcessContext {
            pid: 1,
            ppid: 0,
            executable: "/bin/tool".to_string(),
        },
        operation: FileOperation::Open,
        file: FileContext {
            path: "/tmp/file".to_string(),
            mode: FileOpenMode {
                access: FileAccessMode::Read,
                create: false,
                truncate: false,
                append: false,
                exclusive: false,
            },
        },
    };

    let (first, replay) = tokio::join!(
        state.publish_once("request".to_string(), event.clone()),
        state.publish_once("request".to_string(), event),
    );

    assert_eq!(first, AuditResponse::Accepted);
    assert_eq!(replay, AuditResponse::Accepted);
    assert_eq!(published.load(Ordering::Relaxed), 1);

    let different = AuditEventRequest::File {
        trace_id: "different".to_string(),
        process: ProcessContext {
            pid: 1,
            ppid: 0,
            executable: "/bin/tool".to_string(),
        },
        operation: FileOperation::Open,
        file: FileContext {
            path: "/tmp/file".to_string(),
            mode: FileOpenMode {
                access: FileAccessMode::Read,
                create: false,
                truncate: false,
                append: false,
                exclusive: false,
            },
        },
    };
    assert!(matches!(
        state.publish_once("request".to_string(), different).await,
        AuditResponse::Error {
            errno: libc::EPROTO,
            ..
        }
    ));
    assert_eq!(published.load(Ordering::Relaxed), 1);
}

fn file_event(trace_id: &str) -> AuditEventRequest {
    AuditEventRequest::File {
        trace_id: trace_id.to_string(),
        process: ProcessContext {
            pid: 1,
            ppid: 0,
            executable: "/bin/tool".to_string(),
        },
        operation: FileOperation::Open,
        file: FileContext {
            path: "/tmp/file".to_string(),
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

#[tokio::test]
async fn audit_request_cache_replays_waiters_and_bounds_completed_entries() {
    let fingerprint = [1_u8; 32];
    let mut cache = AuditRequestCache::default();
    assert!(matches!(
        cache.begin("pending".to_string(), fingerprint),
        AuditCacheDecision::Execute
    ));
    let AuditCacheDecision::Wait(waiter) = cache.begin("pending".to_string(), fingerprint) else {
        panic!("matching pending request must wait");
    };
    assert!(matches!(
        cache.begin("pending".to_string(), [2_u8; 32]),
        AuditCacheDecision::Reject
    ));
    cache.complete(
        "missing".to_string(),
        AuditResponse::Accepted,
        Instant::now(),
    );
    cache.complete(
        "pending".to_string(),
        AuditResponse::Accepted,
        Instant::now(),
    );
    assert_eq!(waiter.await.unwrap(), AuditResponse::Accepted);
    assert!(matches!(
        cache.begin("pending".to_string(), fingerprint),
        AuditCacheDecision::Replay(AuditResponse::Accepted)
    ));

    let now = Instant::now();
    cache.entries.insert(
        "live-pending".to_string(),
        CachedAuditRequest::Pending {
            fingerprint,
            waiters: Vec::new(),
        },
    );
    cache.entries.insert(
        "expired".to_string(),
        CachedAuditRequest::Completed {
            fingerprint,
            response: AuditResponse::Accepted,
            completed_at: now - AUDIT_REQUEST_TTL - Duration::from_secs(1),
        },
    );
    for index in 0..=AUDIT_REQUEST_CAPACITY {
        cache.entries.insert(
            format!("capacity-{index}"),
            CachedAuditRequest::Completed {
                fingerprint,
                response: AuditResponse::Accepted,
                completed_at: now,
            },
        );
    }

    cache.prune(now);

    assert!(cache.entries.contains_key("live-pending"));
    assert!(!cache.entries.contains_key("expired"));
    assert_eq!(
        cache
            .entries
            .values()
            .filter(|entry| matches!(entry, CachedAuditRequest::Completed { .. }))
            .count(),
        AUDIT_REQUEST_CAPACITY
    );
}

#[tokio::test]
async fn cancelled_duplicate_audit_request_returns_an_io_error() {
    let event = file_event("trace");
    let fingerprint = audit_event_fingerprint(&event).unwrap();
    let state = Arc::new(AuditState {
        token: "token".to_string(),
        sandbox_id: "sandbox".to_string(),
        run_id: "run".to_string(),
        callback: |_| std::future::ready(Decision::Allow),
        callback_timeout: Duration::from_secs(1),
        requests: Mutex::new(AuditRequestCache {
            entries: HashMap::from([(
                "cancelled".to_string(),
                CachedAuditRequest::Pending {
                    fingerprint,
                    waiters: Vec::new(),
                },
            )]),
        }),
    });
    let waiting = Arc::clone(&state);
    let task =
        tokio::spawn(async move { waiting.publish_once("cancelled".to_string(), event).await });

    loop {
        let mut requests = state.requests.lock().await;
        let waiting = matches!(
            requests.entries.get("cancelled"),
            Some(CachedAuditRequest::Pending { waiters, .. }) if !waiters.is_empty()
        );
        if waiting {
            requests.entries.clear();
            break;
        }
        drop(requests);
        tokio::task::yield_now().await;
    }

    assert!(matches!(
        task.await.unwrap(),
        AuditResponse::Error {
            errno: libc::EIO,
            ..
        }
    ));
    assert!(state.publish(AuditEventRequest::Ping).await.is_err());
}

#[tokio::test]
async fn audit_server_rejects_invalid_follow_up_frames_on_both_connection_modes() {
    for persistent in [false, true] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let state = Arc::new(AuditState {
            token: "token".to_string(),
            sandbox_id: "sandbox".to_string(),
            run_id: "run".to_string(),
            callback: |_| std::future::ready(Decision::Allow),
            callback_timeout: Duration::from_secs(1),
            requests: Mutex::new(AuditRequestCache::default()),
        });
        let task = tokio::spawn(AuditServer::handle_with_timeouts(
            server,
            state,
            Duration::from_secs(1),
            Duration::from_secs(1),
        ));
        let first = if persistent {
            encode_ping_request("token").unwrap()
        } else {
            encode_request("token", file_event("trace")).unwrap()
        };
        client.write_all(&first).await.unwrap();
        let mut prefix = [0_u8; 4];
        client.read_exact(&mut prefix).await.unwrap();
        let mut response = vec![0_u8; frame_length(prefix).unwrap()];
        client.read_exact(&mut response).await.unwrap();
        client.write_all(&0_u32.to_be_bytes()).await.unwrap();

        assert!(task.await.unwrap().is_err());
    }
}

#[test]
fn disconnected_recognizes_only_terminal_socket_errors() {
    for kind in [
        std::io::ErrorKind::UnexpectedEof,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::BrokenPipe,
    ] {
        assert!(disconnected(&std::io::Error::from(kind).into()));
    }
    assert!(!disconnected(
        &std::io::Error::from(std::io::ErrorKind::InvalidData).into()
    ));
    assert!(!disconnected(&anyhow::anyhow!("not an I/O error")));
}
