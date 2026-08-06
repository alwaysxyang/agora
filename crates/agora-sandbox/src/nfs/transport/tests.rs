use super::{MAX_FRAME_SIZE, receive, send};
use crate::nfs::protocol::{PROTOCOL_VERSION, Response, ResponseEnvelope};
use std::io::{Read, Write};
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

#[test]
fn framed_transport_round_trips_without_a_descriptor() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let response = ResponseEnvelope {
        version: PROTOCOL_VERSION,
        response: Response::Success,
    };

    send(&mut sender, &response, None).unwrap();
    let (decoded, descriptor) = receive::<ResponseEnvelope>(&mut receiver).unwrap();

    assert_eq!(decoded, response);
    assert!(descriptor.is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn framed_transport_disables_sigpipe_without_a_descriptor() {
    let (mut sender, _receiver) = UnixStream::pair().unwrap();
    let response = ResponseEnvelope {
        version: PROTOCOL_VERSION,
        response: Response::Success,
    };

    send(&mut sender, &response, None).unwrap();

    let mut enabled = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&mut enabled as *mut libc::c_int).cast(),
                &mut length,
            )
        },
        0
    );
    assert_eq!(enabled, 1);
}

#[test]
fn framed_transport_passes_one_close_on_exec_descriptor() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("payload");
    std::fs::write(&path, b"remote bytes").unwrap();
    let file = std::fs::File::open(path).unwrap();
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let response = ResponseEnvelope {
        version: PROTOCOL_VERSION,
        response: Response::Success,
    };

    send(&mut sender, &response, Some(file.as_raw_fd())).unwrap();
    let (_, descriptor) = receive::<ResponseEnvelope>(&mut receiver).unwrap();
    let descriptor = descriptor.unwrap();
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
    let mut received = unsafe { std::fs::File::from_raw_fd(descriptor.as_raw_fd()) };
    std::mem::forget(descriptor);
    let mut contents = String::new();
    received.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "remote bytes");
}

#[test]
fn framed_transport_rejects_oversized_payloads_before_allocation() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    sender.write_all(&[0]).unwrap();
    sender
        .write_all(&u32::try_from(MAX_FRAME_SIZE + 1).unwrap().to_be_bytes())
        .unwrap();

    let error = receive::<ResponseEnvelope>(&mut receiver).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn framed_transport_rejects_truncated_descriptor_control_messages() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let first = std::fs::File::open("/dev/null").unwrap();
    let second = std::fs::File::open("/dev/null").unwrap();
    send_descriptor_marker(&sender, &[first.as_raw_fd(), second.as_raw_fd()]);
    let payload = serde_json::to_vec(&ResponseEnvelope {
        version: PROTOCOL_VERSION,
        response: Response::Success,
    })
    .unwrap();
    sender
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    sender.write_all(&payload).unwrap();

    let error = receive::<ResponseEnvelope>(&mut receiver).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

fn send_descriptor_marker(stream: &UnixStream, descriptors: &[RawFd]) {
    let mut marker = [0_u8];
    let mut iov = libc::iovec {
        iov_base: marker.as_mut_ptr().cast(),
        iov_len: marker.len(),
    };
    let descriptor_bytes = std::mem::size_of_val(descriptors) as u32;
    let control_length = unsafe { libc::CMSG_SPACE(descriptor_bytes) as usize };
    let mut control = vec![0_u8; control_length];
    let mut header = unsafe { zeroed::<libc::msghdr>() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast();
    header.msg_controllen = control.len() as _;
    unsafe {
        let message = libc::CMSG_FIRSTHDR(&header);
        assert!(!message.is_null());
        (*message).cmsg_level = libc::SOL_SOCKET;
        (*message).cmsg_type = libc::SCM_RIGHTS;
        (*message).cmsg_len = libc::CMSG_LEN(descriptor_bytes) as _;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            libc::CMSG_DATA(message).cast::<RawFd>(),
            descriptors.len(),
        );
        header.msg_controllen = (*message).cmsg_len as _;
        assert_eq!(libc::sendmsg(stream.as_raw_fd(), &header, 0), 1);
    }
}
