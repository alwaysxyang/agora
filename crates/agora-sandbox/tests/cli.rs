use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn hook_library() -> PathBuf {
    static HOOK: OnceLock<PathBuf> = OnceLock::new();
    HOOK.get_or_init(|| {
        let workspace = workspace_root();
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "agora-sandbox", "--lib"])
            .current_dir(&workspace)
            .status()
            .unwrap();
        assert!(status.success());
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                }
            })
            .unwrap_or_else(|| workspace.join("target"));
        let library = target.join("debug/libagora_sandbox.dylib");
        assert!(library.is_file(), "missing {}", library.display());
        library
    })
    .clone()
}

#[test]
fn sandbox_cli_documents_command_and_network_options() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .arg("--help")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-c, --command <COMMAND>"));
    assert!(stdout.contains("--hook-library <HOOK_LIBRARY>"));
    assert!(stdout.contains("--network-enforcement <NETWORK_ENFORCEMENT>"));
    assert!(stdout.contains("--tls <TLS>"));
    assert!(stdout.contains("audit"));
    assert!(stdout.contains("strict"));
}

#[test]
fn sandbox_cli_requires_a_command() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--command <COMMAND>"));
}

#[test]
fn intercepted_cli_child() {
    if std::env::var_os("AGORA_SANDBOX_TEST_CLI_CHILD").is_none() {
        return;
    }

    let destination = std::env::var("AGORA_SANDBOX_TEST_DESTINATION").unwrap();
    let mut stream = TcpStream::connect(destination).unwrap();
    stream.write_all(b"cli-hook").unwrap();
    let mut echoed = [0_u8; 8];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"cli-hook");
}

#[test]
fn sandbox_cli_injects_the_hook_into_the_target_command() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let destination = listener.local_addr().unwrap();
    let echo = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut bytes = [0_u8; 8];
        stream.read_exact(&mut bytes).unwrap();
        stream.write_all(&bytes).unwrap();
    });
    let test_binary = std::env::current_exe().unwrap();
    let command = format!(
        "'{}' intercepted_cli_child --exact --nocapture",
        test_binary.display()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_agora-sandbox"))
        .args([
            "--hook-library",
            hook_library().to_str().unwrap(),
            "-c",
            &command,
        ])
        .env("AGORA_SANDBOX_TEST_CLI_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string())
        .output()
        .unwrap();

    echo.join().unwrap();
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("network.connect.attempt"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
