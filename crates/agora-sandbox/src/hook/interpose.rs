#![cfg(target_os = "macos")]

use super::config::HookConfig;
use super::socket::{RawSocketAddress, set_errno, socket_addr_from_raw};
use crate::protocol::{
    ConnectRequest, HookOperation, PROTOCOL_VERSION, ProcessIdentity, encode_connect_request,
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
    process: ProcessContext,
}

pub(super) struct ProcessContext {
    executable: String,
    next_connection: AtomicU64,
}

impl ProcessContext {
    pub(super) fn new(executable: String) -> Self {
        Self {
            executable,
            next_connection: AtomicU64::new(1),
        }
    }

    fn snapshot(&self) -> (String, ProcessIdentity) {
        self.snapshot_for(std::process::id(), unsafe { libc::getppid() as u32 })
    }

    pub(super) fn snapshot_for(&self, pid: u32, ppid: u32) -> (String, ProcessIdentity) {
        let sequence = self.next_connection.fetch_add(1, Ordering::Relaxed);
        (
            format!("{pid}-{sequence}"),
            ProcessIdentity {
                pid,
                ppid,
                executable: self.executable.clone(),
            },
        )
    }
}

impl HookRuntime {
    fn global() -> Option<&'static Self> {
        static RUNTIME: OnceLock<Option<HookRuntime>> = OnceLock::new();
        RUNTIME
            .get_or_init(|| {
                HookConfig::from_environment().ok().map(|config| Self {
                    config,
                    process: ProcessContext::new(
                        std::env::current_exe()
                            .map(|path| path.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    ),
                })
            })
            .as_ref()
    }

    unsafe fn intercept_connect(
        &self,
        socket: libc::c_int,
        destination: SocketAddr,
        operation: HookOperation,
        original_connectx: ConnectxFn,
    ) -> libc::c_int {
        let (connection_id, process) = self.process.snapshot();
        let request = ConnectRequest {
            protocol_version: PROTOCOL_VERSION,
            token: self.config.token().to_string(),
            connection_id,
            destination,
            process,
            operation,
        };
        let request = match encode_connect_request(&request) {
            Ok(request) => request,
            Err(_) => return unsafe { Self::deny() },
        };

        let proxy = RawSocketAddress::new(self.config.proxy_for(destination));
        let endpoints = SocketEndpoints {
            source_interface: 0,
            source_address: std::ptr::null(),
            source_address_length: 0,
            destination_address: proxy.as_ptr(),
            destination_address_length: proxy.len(),
        };
        let vector = libc::iovec {
            iov_base: request.as_ptr().cast_mut().cast(),
            iov_len: request.len(),
        };
        let mut bytes_written = 0;
        let result = unsafe {
            original_connectx(
                socket,
                std::ptr::addr_of!(endpoints),
                0,
                0,
                std::ptr::addr_of!(vector),
                1,
                std::ptr::addr_of_mut!(bytes_written),
                std::ptr::null_mut(),
            )
        };
        if result == 0 && bytes_written != request.len() {
            unsafe { libc::shutdown(socket, libc::SHUT_RDWR) };
            unsafe { set_errno(libc::EPROTO) };
            return -1;
        }
        result
    }

    unsafe fn intercepted_destination(
        socket: libc::c_int,
        address: *const libc::sockaddr,
        length: libc::socklen_t,
    ) -> Result<Option<SocketAddr>, ()> {
        let Some(destination) = (unsafe { socket_addr_from_raw(address, length) }) else {
            return Ok(None);
        };
        let mut socket_type = 0;
        let mut type_length = mem::size_of_val(&socket_type) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                std::ptr::addr_of_mut!(socket_type).cast(),
                &mut type_length,
            )
        } != 0
        {
            return Err(());
        }
        Ok((socket_type == libc::SOCK_STREAM).then_some(destination))
    }

    unsafe fn deny() -> libc::c_int {
        unsafe { set_errno(libc::EACCES) };
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_connect(
    socket: libc::c_int,
    address: *const libc::sockaddr,
    length: libc::socklen_t,
) -> libc::c_int {
    let Some(original) = original_connect() else {
        unsafe { set_errno(libc::ENOSYS) };
        return -1;
    };
    let destination = match unsafe { HookRuntime::intercepted_destination(socket, address, length) }
    {
        Ok(Some(destination)) => destination,
        Ok(None) => return unsafe { original(socket, address, length) },
        Err(()) => return -1,
    };
    if !HOOK_INITIALIZED.load(Ordering::Acquire) {
        return unsafe { HookRuntime::deny() };
    }
    let Some(runtime) = HookRuntime::global() else {
        return unsafe { HookRuntime::deny() };
    };
    if runtime.config.is_proxy(destination) {
        return unsafe { original(socket, address, length) };
    }
    let Some(connectx) = original_connectx() else {
        return unsafe { HookRuntime::deny() };
    };
    let Some(_guard) = HookGuard::enter() else {
        return unsafe { HookRuntime::deny() };
    };
    catch_unwind(AssertUnwindSafe(|| unsafe {
        runtime.intercept_connect(socket, destination, HookOperation::Connect, connectx)
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
    let Some(original) = original_connectx() else {
        unsafe { set_errno(libc::ENOSYS) };
        return -1;
    };
    if endpoints.is_null() {
        unsafe { set_errno(libc::EINVAL) };
        return -1;
    }
    let endpoints = unsafe { &*endpoints };
    let destination = match unsafe {
        HookRuntime::intercepted_destination(
            socket,
            endpoints.destination_address,
            endpoints.destination_address_length,
        )
    } {
        Ok(Some(destination)) => destination,
        Ok(None) => {
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
        }
        Err(()) => return -1,
    };
    if !HOOK_INITIALIZED.load(Ordering::Acquire) {
        return unsafe { HookRuntime::deny() };
    }
    let Some(runtime) = HookRuntime::global() else {
        return unsafe { HookRuntime::deny() };
    };
    if runtime.config.is_proxy(destination) {
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
    }
    let simple = association_id == 0
        && flags == 0
        && vector_count == 0
        && endpoints.source_interface == 0
        && endpoints.source_address.is_null()
        && endpoints.source_address_length == 0;
    if !simple {
        return unsafe { HookRuntime::deny() };
    }
    if !bytes_written.is_null() {
        unsafe { *bytes_written = 0 };
    }
    if !connection_id.is_null() {
        unsafe { *connection_id = 0 };
    }
    let Some(_guard) = HookGuard::enter() else {
        return unsafe { HookRuntime::deny() };
    };
    catch_unwind(AssertUnwindSafe(|| unsafe {
        runtime.intercept_connect(socket, destination, HookOperation::Connectx, original)
    }))
    .unwrap_or_else(|_| {
        unsafe { set_errno(libc::EIO) };
        -1
    })
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
