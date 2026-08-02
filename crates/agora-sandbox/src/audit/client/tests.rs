use super::{AuditError, io};

#[test]
fn audit_error_maps_io_failures_to_stable_errno_values() {
    for (kind, expected) in [
        (io::ErrorKind::PermissionDenied, libc::EACCES),
        (io::ErrorKind::InvalidInput, libc::EINVAL),
        (io::ErrorKind::InvalidData, libc::EINVAL),
        (io::ErrorKind::TimedOut, libc::ETIMEDOUT),
        (io::ErrorKind::ConnectionRefused, libc::EIO),
    ] {
        let error = AuditError::from_io(io::Error::new(kind, "audit failure"));
        assert_eq!(error.errno(), expected);
        assert_eq!(error.to_string(), "audit failure");
    }

    let error = AuditError::from_io(io::Error::from_raw_os_error(libc::ECONNRESET));
    assert_eq!(error.errno(), libc::ECONNRESET);
}
