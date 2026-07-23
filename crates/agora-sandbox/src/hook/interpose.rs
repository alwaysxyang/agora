#![cfg(target_os = "macos")]

use super::config::HookConfig;
use super::proxy::{BlockingSocket, ProxyClient, ProxyDecision};
use super::socket::{RawSocketAddress, set_errno, socket_addr_from_raw};
use crate::protocol::{
    ConnectRequest, CoverageFallback, CoverageGap, HookOperation, PROTOCOL_VERSION,
    ProcessIdentity, encode_connect_request,
};
use std::cell::Cell;
use std::mem;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

type ConnectFn =
    unsafe extern "C" fn(libc::c_int, *const libc::sockaddr, libc::socklen_t) -> libc::c_int;

type AssociationId = u32;
type ConnectionId = u32;

#[repr(C)]
pub(crate) struct SocketEndpoints {
    source_interface: libc::c_uint,
    source_address: *const libc::sockaddr,
    source_address_length: libc::socklen_t,
    destination_address: *const libc::sockaddr,
    destination_address_length: libc::socklen_t,
}

type ConnectxFn = unsafe extern "C" fn(
    libc::c_int,
    *const SocketEndpoints,
    AssociationId,
    libc::c_uint,
    *const libc::iovec,
    libc::c_uint,
    *mut libc::size_t,
    *mut ConnectionId,
) -> libc::c_int;

thread_local! {
    static INSIDE_HOOK: Cell<bool> = const { Cell::new(false) };
}

static HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);

extern "C" fn initialize_hook() {
    HOOK_INITIALIZED.store(true, Ordering::Release);
}

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static HOOK_INITIALIZER: extern "C" fn() = initialize_hook;

struct HookGuard;

impl HookGuard {
    fn enter() -> Option<Self> {
        INSIDE_HOOK.with(|inside| {
            if inside.replace(true) {
                None
            } else {
                Some(Self)
            }
        })
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        INSIDE_HOOK.with(|inside| inside.set(false));
    }
}

struct HookRuntime {
    config: HookConfig,
    process: ProcessIdentity,
    next_connection: AtomicU64,
}

impl HookRuntime {
    fn global() -> Option<&'static Self> {
        static RUNTIME: OnceLock<Option<HookRuntime>> = OnceLock::new();
        RUNTIME
            .get_or_init(|| {
                HookConfig::from_environment().ok().map(|config| Self {
                    config,
                    process: ProcessIdentity {
                        pid: std::process::id(),
                        ppid: unsafe { libc::getppid() as u32 },
                        executable: std::env::current_exe()
                            .map(|path| path.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    },
                    next_connection: AtomicU64::new(1),
                })
            })
            .as_ref()
    }

    unsafe fn intercept_connect(
        &self,
        socket: libc::c_int,
        destination_address: *const libc::sockaddr,
        destination_length: libc::socklen_t,
        operation: HookOperation,
        original: ConnectFn,
    ) -> libc::c_int {
        let destination = unsafe { socket_addr_from_raw(destination_address, destination_length) };
        let Some(destination) = destination else {
            return unsafe { original(socket, destination_address, destination_length) };
        };
        if !unsafe { Self::is_stream_socket(socket) } || self.config.is_proxy(destination) {
            return unsafe { original(socket, destination_address, destination_length) };
        }

        let connection_id = format!(
            "{}-{}",
            self.process.pid,
            self.next_connection.fetch_add(1, Ordering::Relaxed)
        );
        let request = ConnectRequest {
            protocol_version: PROTOCOL_VERSION,
            token: self.config.token().to_string(),
            sandbox_id: self.config.sandbox_id().to_string(),
            run_id: self.config.run_id().to_string(),
            connection_id: connection_id.clone(),
            destination,
            process: self.process.clone(),
            operation,
        };
        let request = match encode_connect_request(&request) {
            Ok(request) => request,
            Err(error) => {
                return unsafe {
                    self.coverage_fallback(
                        socket,
                        destination_address,
                        destination_length,
                        Some(destination),
                        connection_id,
                        operation,
                        format!("failed to encode proxy CONNECT request: {error}"),
                        original,
                    )
                };
            }
        };

        let blocking = match unsafe { BlockingSocket::new(socket) } {
            Ok(blocking) => blocking,
            Err(reason) => {
                return unsafe {
                    self.coverage_fallback(
                        socket,
                        destination_address,
                        destination_length,
                        Some(destination),
                        connection_id,
                        operation,
                        reason,
                        original,
                    )
                };
            }
        };

        let proxy = RawSocketAddress::new(self.config.proxy_for(destination));
        if unsafe { original(socket, proxy.as_ptr(), proxy.len()) } != 0 {
            let reason = format!(
                "failed to connect intercepted socket to sandbox proxy: {}",
                std::io::Error::last_os_error()
            );
            drop(blocking);
            return unsafe {
                self.coverage_fallback(
                    socket,
                    destination_address,
                    destination_length,
                    Some(destination),
                    connection_id,
                    operation,
                    reason,
                    original,
                )
            };
        }

        let decision = unsafe { ProxyClient::new(&self.config).handshake(socket, &request) };
        drop(blocking);
        match decision {
            Ok(ProxyDecision::Accepted) => 0,
            Ok(ProxyDecision::Rejected { errno }) => {
                unsafe { set_errno(errno) };
                -1
            }
            Err(reason) => {
                self.report_connected_proxy_gap(
                    Some(destination),
                    connection_id,
                    operation,
                    reason,
                );
                unsafe { set_errno(libc::EPROTO) };
                -1
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn coverage_fallback(
        &self,
        socket: libc::c_int,
        destination_address: *const libc::sockaddr,
        destination_length: libc::socklen_t,
        destination: Option<SocketAddr>,
        connection_id: String,
        operation: HookOperation,
        reason: String,
        original: ConnectFn,
    ) -> libc::c_int {
        let fallback = if self.config.fail_open() {
            CoverageFallback::FailOpen
        } else {
            CoverageFallback::FailClosed
        };
        let _ = ProxyClient::new(&self.config).report_coverage_gap(&CoverageGap {
            protocol_version: PROTOCOL_VERSION,
            token: self.config.token().to_string(),
            sandbox_id: self.config.sandbox_id().to_string(),
            run_id: self.config.run_id().to_string(),
            connection_id: Some(connection_id),
            destination,
            process: self.process.clone(),
            operation,
            reason,
            fallback,
        });
        if self.config.fail_open() {
            unsafe { original(socket, destination_address, destination_length) }
        } else {
            unsafe { set_errno(libc::EACCES) };
            -1
        }
    }

    unsafe fn report_connectx_gap(&self, destination: Option<SocketAddr>, reason: &str) -> bool {
        let fallback = if self.config.fail_open() {
            CoverageFallback::FailOpen
        } else {
            CoverageFallback::FailClosed
        };
        let connection_id = format!(
            "{}-{}",
            self.process.pid,
            self.next_connection.fetch_add(1, Ordering::Relaxed)
        );
        let _ = ProxyClient::new(&self.config).report_coverage_gap(&CoverageGap {
            protocol_version: PROTOCOL_VERSION,
            token: self.config.token().to_string(),
            sandbox_id: self.config.sandbox_id().to_string(),
            run_id: self.config.run_id().to_string(),
            connection_id: Some(connection_id),
            destination,
            process: self.process.clone(),
            operation: HookOperation::Connectx,
            reason: reason.to_string(),
            fallback,
        });
        self.config.fail_open()
    }

    fn report_connected_proxy_gap(
        &self,
        destination: Option<SocketAddr>,
        connection_id: String,
        operation: HookOperation,
        reason: String,
    ) {
        let _ = ProxyClient::new(&self.config).report_coverage_gap(&CoverageGap {
            protocol_version: PROTOCOL_VERSION,
            token: self.config.token().to_string(),
            sandbox_id: self.config.sandbox_id().to_string(),
            run_id: self.config.run_id().to_string(),
            connection_id: Some(connection_id),
            destination,
            process: self.process.clone(),
            operation,
            reason,
            fallback: CoverageFallback::FailClosed,
        });
    }

    unsafe fn is_stream_socket(socket: libc::c_int) -> bool {
        let mut socket_type = 0;
        let mut length = mem::size_of_val(&socket_type) as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                std::ptr::addr_of_mut!(socket_type).cast(),
                &mut length,
            ) == 0
                && socket_type == libc::SOCK_STREAM
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_connect(
    socket: libc::c_int,
    address: *const libc::sockaddr,
    length: libc::socklen_t,
) -> libc::c_int {
    if !HOOK_INITIALIZED.load(Ordering::Acquire) {
        return match original_connect() {
            Some(original) => unsafe { original(socket, address, length) },
            None => -1,
        };
    }
    let Some(original) = original_connect() else {
        unsafe { set_errno(libc::ENOSYS) };
        return -1;
    };
    let Some(_guard) = HookGuard::enter() else {
        return unsafe { original(socket, address, length) };
    };
    let Some(runtime) = HookRuntime::global() else {
        return unsafe { original(socket, address, length) };
    };
    catch_unwind(AssertUnwindSafe(|| unsafe {
        runtime.intercept_connect(socket, address, length, HookOperation::Connect, original)
    }))
    .unwrap_or_else(|_| {
        unsafe { set_errno(libc::EIO) };
        -1
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_connectx(
    socket: libc::c_int,
    endpoints: *const SocketEndpoints,
    association_id: AssociationId,
    flags: libc::c_uint,
    vectors: *const libc::iovec,
    vector_count: libc::c_uint,
    bytes_written: *mut libc::size_t,
    connection_id: *mut ConnectionId,
) -> libc::c_int {
    if !HOOK_INITIALIZED.load(Ordering::Acquire) {
        return match original_connectx() {
            Some(original) => unsafe {
                original(
                    socket,
                    endpoints,
                    association_id,
                    flags,
                    vectors,
                    vector_count,
                    bytes_written,
                    connection_id,
                )
            },
            None => -1,
        };
    }
    let Some(original) = original_connectx() else {
        unsafe { set_errno(libc::ENOSYS) };
        return -1;
    };
    let Some(_guard) = HookGuard::enter() else {
        return unsafe {
            original(
                socket,
                endpoints,
                association_id,
                flags,
                vectors,
                vector_count,
                bytes_written,
                connection_id,
            )
        };
    };
    let Some(runtime) = HookRuntime::global() else {
        return unsafe {
            original(
                socket,
                endpoints,
                association_id,
                flags,
                vectors,
                vector_count,
                bytes_written,
                connection_id,
            )
        };
    };
    if endpoints.is_null() {
        unsafe { set_errno(libc::EINVAL) };
        return -1;
    }
    let endpoints = unsafe { &*endpoints };
    let destination = unsafe {
        socket_addr_from_raw(
            endpoints.destination_address,
            endpoints.destination_address_length,
        )
    };
    let simple = association_id == 0
        && flags == 0
        && vector_count == 0
        && endpoints.source_interface == 0
        && endpoints.source_address.is_null();
    if simple {
        let Some(connect) = original_connect() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let result = catch_unwind(AssertUnwindSafe(|| unsafe {
            runtime.intercept_connect(
                socket,
                endpoints.destination_address,
                endpoints.destination_address_length,
                HookOperation::Connectx,
                connect,
            )
        }))
        .unwrap_or_else(|_| {
            unsafe { set_errno(libc::EIO) };
            -1
        });
        if result == 0 {
            if !bytes_written.is_null() {
                unsafe { *bytes_written = 0 };
            }
            if !connection_id.is_null() {
                unsafe { *connection_id = 0 };
            }
        }
        return result;
    }

    if unsafe {
        runtime.report_connectx_gap(
            destination,
            "connectx options with source binding, flags, or initial data are not intercepted",
        )
    } {
        unsafe {
            original(
                socket,
                endpoints,
                association_id,
                flags,
                vectors,
                vector_count,
                bytes_written,
                connection_id,
            )
        }
    } else {
        unsafe { set_errno(libc::EACCES) };
        -1
    }
}

fn original_connect() -> Option<ConnectFn> {
    function_from_interpose(&INTERPOSE_CONNECT)
}

fn original_connectx() -> Option<ConnectxFn> {
    function_from_interpose(&INTERPOSE_CONNECTX)
}

fn function_from_interpose<T>(interpose: &DyldInterpose) -> Option<T>
where
    T: Copy,
{
    if interpose.replacee.is_null() {
        None
    } else {
        Some(unsafe { mem::transmute_copy(&interpose.replacee) })
    }
}

#[repr(C)]
struct DyldInterpose {
    replacement: *const libc::c_void,
    replacee: *const libc::c_void,
}

unsafe impl Sync for DyldInterpose {}

macro_rules! dyld_interpose {
    ($name:ident, $replacement:path, $replacee:path) => {
        #[used]
        #[unsafe(link_section = "__DATA,__interpose")]
        static $name: DyldInterpose = DyldInterpose {
            replacement: $replacement as *const () as *const libc::c_void,
            replacee: $replacee as *const () as *const libc::c_void,
        };
    };
}

unsafe extern "C" {
    #[link_name = "connectx"]
    fn system_connectx(
        socket: libc::c_int,
        endpoints: *const SocketEndpoints,
        association_id: AssociationId,
        flags: libc::c_uint,
        vectors: *const libc::iovec,
        vector_count: libc::c_uint,
        bytes_written: *mut libc::size_t,
        connection_id: *mut ConnectionId,
    ) -> libc::c_int;
}

dyld_interpose!(INTERPOSE_CONNECT, agora_sandbox_connect, libc::connect);
dyld_interpose!(INTERPOSE_CONNECTX, agora_sandbox_connectx, system_connectx);
