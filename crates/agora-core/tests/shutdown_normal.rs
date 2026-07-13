use agora_core::lifecycle::shutdown::{ShutdownGuard, ShutdownReason, on_shutdown};
use std::sync::{Arc, Mutex};

#[test]
fn dropping_the_singleton_guard_notifies_subscribers_with_normal_reason() {
    let received = Arc::new(Mutex::new(None));
    let callback_received = Arc::clone(&received);
    on_shutdown(move |reason| {
        *callback_received.lock().unwrap() = Some(reason);
        Ok(())
    })
    .unwrap();

    let guard = ShutdownGuard::get();
    let same_guard = ShutdownGuard::get();
    assert!(Arc::ptr_eq(&guard, &same_guard));
    drop(same_guard);
    assert_eq!(*received.lock().unwrap(), None);
    drop(guard);

    assert_eq!(*received.lock().unwrap(), Some(ShutdownReason::Normal));
}
