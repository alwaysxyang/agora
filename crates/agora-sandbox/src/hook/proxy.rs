use super::config::HookConfig;
use crate::protocol::{
    CoverageGap, HANDSHAKE_TIMEOUT, MAX_FRAME_SIZE, encode_coverage_gap_request,
    parse_proxy_response,
};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Instant;

pub(super) enum ProxyDecision {
    Accepted,
    Rejected { errno: i32 },
}

pub(super) struct BlockingSocket {
    socket: libc::c_int,
    flags: libc::c_int,
    changed: bool,
}

impl BlockingSocket {
    pub(super) unsafe fn new(socket: libc::c_int) -> Result<Self, String> {
        let flags = unsafe { libc::fcntl(socket, libc::F_GETFL) };
        if flags < 0 {
            return Err(format!(
                "failed to inspect intercepted socket flags: {}",
                io::Error::last_os_error()
            ));
        }
        let changed = flags & libc::O_NONBLOCK != 0;
        if changed && unsafe { libc::fcntl(socket, libc::F_SETFL, flags & !libc::O_NONBLOCK) } != 0
        {
            return Err(format!(
                "failed to make intercepted socket blocking: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(Self {
            socket,
            flags,
            changed,
        })
    }
}

impl Drop for BlockingSocket {
    fn drop(&mut self) {
        if self.changed {
            unsafe {
                libc::fcntl(self.socket, libc::F_SETFL, self.flags);
            }
        }
    }
}

pub(super) struct ProxyClient<'a> {
    config: &'a HookConfig,
}

impl<'a> ProxyClient<'a> {
    pub(super) fn new(config: &'a HookConfig) -> Self {
        Self { config }
    }

    pub(super) unsafe fn handshake(
        &self,
        socket: libc::c_int,
        request: &[u8],
    ) -> Result<ProxyDecision, String> {
        let _no_sigpipe = unsafe { NoSigpipe::new(socket) }
            .map_err(|error| format!("failed to configure proxy handshake: {error}"))?;
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        unsafe { send_all(socket, request, deadline) }
            .map_err(|error| format!("proxy CONNECT request failed: {error}"))?;
        let head = unsafe { read_head(socket, deadline) }
            .map_err(|error| format!("proxy CONNECT response failed: {error}"))?;
        let response = parse_proxy_response(&head)
            .map_err(|error| format!("invalid proxy CONNECT response: {error}"))?;
        if response.status == 200 {
            return Ok(ProxyDecision::Accepted);
        }
        Ok(ProxyDecision::Rejected {
            errno: response
                .errno
                .unwrap_or_else(|| status_errno(response.status)),
        })
    }

    pub(super) fn report_coverage_gap(&self, gap: &CoverageGap) -> Result<(), String> {
        let request = encode_coverage_gap_request(gap)
            .map_err(|error| format!("coverage-gap request encoding failed: {error}"))?;
        let destination = gap
            .destination
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let mut stream = TcpStream::connect(self.config.proxy_for(destination))
            .map_err(|error| format!("coverage-gap proxy connect failed: {error}"))?;
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| format!("coverage-gap read timeout setup failed: {error}"))?;
        stream
            .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|error| format!("coverage-gap write timeout setup failed: {error}"))?;
        stream
            .write_all(&request)
            .map_err(|error| format!("coverage-gap request failed: {error}"))?;
        let head = read_head_from(&mut stream)
            .map_err(|error| format!("coverage-gap response failed: {error}"))?;
        let response = parse_proxy_response(&head)
            .map_err(|error| format!("invalid coverage-gap response: {error}"))?;
        if response.status == 204 {
            Ok(())
        } else {
            Err(format!(
                "coverage-gap request was rejected with HTTP {}",
                response.status
            ))
        }
    }
}

struct NoSigpipe {
    socket: libc::c_int,
    previous: libc::c_int,
    changed: bool,
}

impl NoSigpipe {
    unsafe fn new(socket: libc::c_int) -> io::Result<Self> {
        let mut previous = 0;
        let mut length = std::mem::size_of_val(&previous) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                std::ptr::addr_of_mut!(previous).cast(),
                &mut length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let changed = previous == 0;
        if changed {
            let enabled: libc::c_int = 1;
            if unsafe {
                libc::setsockopt(
                    socket,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    std::ptr::addr_of!(enabled).cast(),
                    std::mem::size_of_val(&enabled) as libc::socklen_t,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            socket,
            previous,
            changed,
        })
    }
}

impl Drop for NoSigpipe {
    fn drop(&mut self) {
        if self.changed {
            unsafe {
                libc::setsockopt(
                    self.socket,
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    std::ptr::addr_of!(self.previous).cast(),
                    std::mem::size_of_val(&self.previous) as libc::socklen_t,
                );
            }
        }
    }
}

unsafe fn send_all(socket: libc::c_int, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        wait_for(socket, libc::POLLOUT, deadline)?;
        let result = unsafe {
            libc::send(
                socket,
                bytes[written..].as_ptr().cast(),
                bytes.len() - written,
                libc::MSG_DONTWAIT,
            )
        };
        if result > 0 {
            written += result as usize;
            continue;
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "proxy connection accepted no request bytes",
            ));
        }
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            continue;
        }
        return Err(error);
    }
    Ok(())
}

unsafe fn read_head(socket: libc::c_int, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    while head.len() < MAX_FRAME_SIZE {
        wait_for(socket, libc::POLLIN, deadline)?;
        let mut byte = 0_u8;
        let result = unsafe {
            libc::recv(
                socket,
                std::ptr::addr_of_mut!(byte).cast(),
                1,
                libc::MSG_DONTWAIT,
            )
        };
        if result == 1 {
            head.push(byte);
            if head.ends_with(b"\r\n\r\n") {
                return Ok(head);
            }
            continue;
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed before completing the HTTP response",
            ));
        }
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            continue;
        }
        return Err(error);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("HTTP response head exceeds {MAX_FRAME_SIZE} bytes"),
    ))
}

fn read_head_from(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(256);
    while head.len() < MAX_FRAME_SIZE {
        let mut byte = 0_u8;
        reader.read_exact(std::slice::from_mut(&mut byte))?;
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("HTTP response head exceeds {MAX_FRAME_SIZE} bytes"),
    ))
}

fn wait_for(socket: libc::c_int, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "proxy handshake timed out"))?;
        let milliseconds = remaining.as_millis().max(1).min(i32::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd: socket,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(std::ptr::addr_of_mut!(descriptor), 1, milliseconds) };
        if result > 0 {
            if descriptor.revents & events != 0 {
                return Ok(());
            }
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!(
                    "proxy socket poll failed with events {:#x}",
                    descriptor.revents
                ),
            ));
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy handshake timed out",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn status_errno(status: u16) -> i32 {
    match status {
        400 | 405 | 505 => libc::EPROTO,
        403 | 407 => libc::EACCES,
        408 | 504 => libc::ETIMEDOUT,
        502 => libc::ECONNREFUSED,
        _ => libc::EIO,
    }
}
