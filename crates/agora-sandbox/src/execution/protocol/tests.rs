use super::{CommandRequest, ProcessOperation, encode_bounded_command};

#[test]
fn bounded_command_rejects_a_budget_smaller_than_required_metadata() {
    let command = CommandRequest {
        trace_id: "trace".to_string(),
        pid: 2,
        ppid: 1,
        process_executable: "/bin/sh".to_string(),
        executable: "/usr/bin/true".to_string(),
        arguments: Vec::new(),
        current_dir: "/tmp".to_string(),
        operation: ProcessOperation::Execve,
    };

    let error = encode_bounded_command(&command, 0).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "command metadata is too large");
}
