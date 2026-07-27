use super::*;
use crate::protocol::parse_connect_request_prefix;
use std::sync::Mutex;

static CAPTURED: Mutex<Option<(ConnectRequest, SocketAddr)>> = Mutex::new(None);
static SHORT_WRITE: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn recording_connectx(
    _socket: libc::c_int,
    endpoints: *const SocketEndpoints,
    _association_id: AssociationId,
    _flags: libc::c_uint,
    vectors: *const libc::iovec,
    vector_count: libc::c_uint,
    bytes_written: *mut libc::size_t,
    _connection_id: *mut ConnectionId,
) -> libc::c_int {
    let endpoints = unsafe { &*endpoints };
    let proxy = unsafe {
        socket_addr_from_raw(
            endpoints.destination_address,
            endpoints.destination_address_length,
        )
    }
    .unwrap();
    let vector = unsafe { &*vectors };
    let request =
        unsafe { std::slice::from_raw_parts(vector.iov_base.cast::<u8>(), vector.iov_len) };
    let request = parse_connect_request_prefix(request).unwrap().unwrap().0;
    *CAPTURED.lock().unwrap() = Some((request, proxy));
    if !bytes_written.is_null() {
        unsafe {
            *bytes_written = if SHORT_WRITE.load(Ordering::Relaxed) && vector_count == 1 {
                vector.iov_len.saturating_sub(1)
            } else {
                vector.iov_len
            };
        }
    }
    0
}

fn runtime() -> HookRuntime {
    let config = HookConfig::from_getter(|key| {
        Some(
            match key {
                "AGORA_SANDBOX_TOKEN" => "hook-token",
                "AGORA_SANDBOX_PROXY_IPV4" => "127.0.0.1:41000",
                "AGORA_SANDBOX_PROXY_IPV6" => "[::1]:41001",
                _ => return None,
            }
            .to_string(),
        )
    })
    .unwrap();
    HookRuntime {
        config,
        process: ProcessContext::new("/tmp/client".to_string()),
    }
}

fn socket(kind: libc::c_int) -> libc::c_int {
    let socket = unsafe { libc::socket(libc::AF_INET, kind, 0) };
    assert!(socket >= 0);
    socket
}

#[test]
fn hook_guard_blocks_recursion_and_reopens_after_drop() {
    let guard = HookGuard::enter().expect("first hook entry should succeed");
    assert!(HookGuard::enter().is_none());
    drop(guard);
    assert!(HookGuard::enter().is_some());
}

#[test]
fn intercepted_destination_accepts_only_valid_stream_sockets() {
    let address = RawSocketAddress::new("203.0.113.10:443".parse().unwrap());
    let stream = socket(libc::SOCK_STREAM);
    let datagram = socket(libc::SOCK_DGRAM);

    assert_eq!(
        unsafe { HookRuntime::intercepted_destination(stream, address.as_ptr(), address.len()) },
        Ok(Some("203.0.113.10:443".parse().unwrap()))
    );
    assert_eq!(
        unsafe { HookRuntime::intercepted_destination(datagram, address.as_ptr(), address.len()) },
        Ok(None)
    );
    assert_eq!(
        unsafe { HookRuntime::intercepted_destination(stream, std::ptr::null(), 0) },
        Ok(None)
    );
    assert_eq!(
        unsafe { HookRuntime::intercepted_destination(-1, address.as_ptr(), address.len()) },
        Err(())
    );

    unsafe {
        libc::close(stream);
        libc::close(datagram);
    }
}

#[test]
fn runtime_encodes_connect_metadata_and_rejects_short_proxy_writes() {
    let runtime = runtime();
    let destination: SocketAddr = "203.0.113.10:443".parse().unwrap();
    let socket = socket(libc::SOCK_STREAM);

    SHORT_WRITE.store(false, Ordering::Relaxed);
    assert_eq!(
        unsafe {
            runtime.intercept_connect(
                socket,
                destination,
                HookOperation::Connectx,
                recording_connectx,
            )
        },
        0
    );
    let (request, proxy) = CAPTURED.lock().unwrap().take().unwrap();
    assert_eq!(request.token, "hook-token");
    assert_eq!(request.destination, destination);
    assert_eq!(request.process.executable, "/tmp/client");
    assert_eq!(request.operation, HookOperation::Connectx);
    assert_eq!(proxy, "127.0.0.1:41000".parse().unwrap());

    SHORT_WRITE.store(true, Ordering::Relaxed);
    assert_eq!(
        unsafe {
            runtime.intercept_connect(
                socket,
                destination,
                HookOperation::Connect,
                recording_connectx,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPROTO)
    );
    SHORT_WRITE.store(false, Ordering::Relaxed);

    unsafe { libc::close(socket) };
}

#[test]
fn exported_hooks_validate_initialization_and_pointer_shapes() {
    initialize_hook();
    assert!(HOOK_INITIALIZED.load(Ordering::Acquire));
    assert!(original_connect().is_some());
    assert!(original_connectx().is_some());

    let null = DyldInterpose {
        replacement: std::ptr::null(),
        replacee: std::ptr::null(),
    };
    assert!(function_from_interpose::<ConnectFn>(&null).is_none());
    let present = DyldInterpose {
        replacement: std::ptr::null(),
        replacee: libc::connect as *const () as *const libc::c_void,
    };
    assert!(function_from_interpose::<ConnectFn>(&present).is_some());

    assert_eq!(
        unsafe {
            agora_sandbox_connectx(
                -1,
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EINVAL)
    );

    let stream = socket(libc::SOCK_STREAM);
    let destination = RawSocketAddress::new("203.0.113.10:443".parse().unwrap());
    HOOK_INITIALIZED.store(false, Ordering::Release);
    assert_eq!(
        unsafe { agora_sandbox_connect(stream, destination.as_ptr(), destination.len()) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EACCES)
    );
    initialize_hook();

    unsafe { libc::close(stream) };
}
