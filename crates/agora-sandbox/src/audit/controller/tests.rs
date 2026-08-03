use super::*;
use crate::callback::Decision;

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
}
