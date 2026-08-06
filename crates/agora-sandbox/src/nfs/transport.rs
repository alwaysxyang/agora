//! Unix socket framing and descriptor transfer for network filesystems.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

pub(crate) const MAX_FRAME_SIZE: usize = 1024 * 1024;
const FRAME_MARKER: u8 = 0;

pub(crate) fn send<T: Serialize>(
    stream: &mut UnixStream,
    message: &T,
    descriptor: Option<RawFd>,
) -> io::Result<()> {
    configure_no_sigpipe(stream.as_raw_fd())?;
    let payload = serde_json::to_vec(message).map_err(invalid_data)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote filesystem frame is too large",
        ));
    }
    send_marker(stream, descriptor)?;
    stream.write_all(
        &u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame is too large"))?
            .to_be_bytes(),
    )?;
    stream.write_all(&payload)
}

pub(crate) fn receive<T: DeserializeOwned>(
    stream: &mut UnixStream,
) -> io::Result<(T, Option<OwnedFd>)> {
    let descriptor = receive_marker(stream)?;
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "remote filesystem frame is too large",
        ));
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    let message = serde_json::from_slice(&payload).map_err(invalid_data)?;
    Ok((message, descriptor))
}

fn send_marker(stream: &UnixStream, descriptor: Option<RawFd>) -> io::Result<()> {
    let Some(descriptor) = descriptor else {
        return (&*stream).write_all(&[FRAME_MARKER]);
    };
    let mut marker = [FRAME_MARKER];
    let mut iov = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let control_length = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize };
    let mut control = vec![0_u8; control_length];
    let mut header = unsafe { zeroed::<libc::msghdr>() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len() as _;
    unsafe {
        let message = libc::CMSG_FIRSTHDR(&header);
        if message.is_null() {
            return Err(io::Error::other(
                "failed to create descriptor control message",
            ));
        }
        (*message).cmsg_level = libc::SOL_SOCKET;
        (*message).cmsg_type = libc::SCM_RIGHTS;
        (*message).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(message).cast::<RawFd>(), descriptor);
        header.msg_controllen = (*message).cmsg_len as _;
    }
    let flags = send_flags();
    let written = unsafe { libc::sendmsg(stream.as_raw_fd(), &header, flags) };
    if written == 1 {
        Ok(())
    } else if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "failed to send remote filesystem frame marker",
        ))
    }
}

fn receive_marker(stream: &UnixStream) -> io::Result<Option<OwnedFd>> {
    let mut marker = [0_u8; 1];
    let mut iov = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let control_length = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize };
    let mut control = vec![0_u8; control_length];
    let mut header = unsafe { zeroed::<libc::msghdr>() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len() as _;
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut header, libc::MSG_WAITALL) };
    if received == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "remote filesystem transport closed",
        ));
    }
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if received != 1 || marker[0] != FRAME_MARKER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid remote filesystem frame marker",
        ));
    }
    let control_start = header.msg_control as usize;
    let control_end = control_start.saturating_add(header.msg_controllen as usize);
    let mut descriptors = Vec::new();
    let mut invalid_control = header.msg_flags & libc::MSG_CTRUNC != 0;
    unsafe {
        let mut message = libc::CMSG_FIRSTHDR(&header);
        while !message.is_null() {
            let message_start = message as usize;
            let base = libc::CMSG_LEN(0) as usize;
            let length = (*message).cmsg_len as usize;
            let data_start = libc::CMSG_DATA(message) as usize;
            if length < base
                || message_start < control_start
                || data_start < message_start
                || data_start > control_end
            {
                invalid_control = true;
                break;
            }
            let Some(declared_end) = message_start.checked_add(length) else {
                invalid_control = true;
                break;
            };
            let available_end = declared_end.min(control_end);
            if declared_end > control_end {
                invalid_control = true;
            }
            if (*message).cmsg_level == libc::SOL_SOCKET && (*message).cmsg_type == libc::SCM_RIGHTS
            {
                let payload = available_end.saturating_sub(data_start);
                if payload % size_of::<RawFd>() != 0 {
                    invalid_control = true;
                }
                for index in 0..(payload / size_of::<RawFd>()) {
                    let raw = std::ptr::read_unaligned(
                        libc::CMSG_DATA(message).cast::<RawFd>().add(index),
                    );
                    if raw < 0 {
                        invalid_control = true;
                    } else {
                        descriptors.push(OwnedFd::from_raw_fd(raw));
                    }
                }
            }
            if declared_end > control_end {
                break;
            }
            message = libc::CMSG_NXTHDR(&header, message);
        }
    }
    if invalid_control || descriptors.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid descriptor control message",
        ));
    }
    let descriptor = descriptors.pop();
    if let Some(descriptor) = descriptor.as_ref() {
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            || unsafe {
                libc::fcntl(
                    descriptor.as_raw_fd(),
                    libc::F_SETFD,
                    flags | libc::FD_CLOEXEC,
                )
            } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(descriptor)
}

#[cfg(target_os = "macos")]
fn configure_no_sigpipe(descriptor: RawFd) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&enabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn configure_no_sigpipe(_descriptor: RawFd) -> io::Result<()> {
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
const fn send_flags() -> libc::c_int {
    libc::MSG_NOSIGNAL
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
const fn send_flags() -> libc::c_int {
    0
}

fn invalid_data(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests;
