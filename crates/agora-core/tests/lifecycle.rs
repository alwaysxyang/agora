use agora_core::lifecycle::shutdown::{
    ShutdownGuard, ShutdownReason, on_shutdown, request_shutdown,
};
use std::sync::{Arc, Mutex};

#[test]
fn registered_callbacks_receive_the_first_shutdown_reason_once() {
    let reasons = Arc::new(Mutex::new(Vec::new()));

    for _ in 0..2 {
        let reasons = Arc::clone(&reasons);
        on_shutdown(move |reason| {
            reasons.lock().unwrap().push(reason);
            Ok(())
        })
        .unwrap();
    }

    let guard = ShutdownGuard::get();
    assert!(request_shutdown("requested by test"));
    assert!(!request_shutdown("ignored second request"));
    drop(guard);

    assert_eq!(
        *reasons.lock().unwrap(),
        vec![
            ShutdownReason::Requested {
                reason: "requested by test".to_string(),
            },
            ShutdownReason::Requested {
                reason: "requested by test".to_string(),
            },
        ]
    );
}
