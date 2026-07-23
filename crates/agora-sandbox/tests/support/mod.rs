use agora_sandbox::audit::{AuditCallback, AuditEvent};
use agora_sandbox::network::{NetworkConfig, NetworkController, NetworkRunContext, NetworkRuntime};
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const PROTOCOL_VERSION: u16 = 3;
const MAX_FRAME_SIZE: usize = 16 * 1024;

#[derive(Clone, Default)]
pub struct EventLog(Arc<Mutex<Vec<AuditEvent>>>);

impl AuditCallback for EventLog {
    fn on_event(&self, event: AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}

impl EventLog {
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.0.lock().unwrap().clone()
    }

    pub async fn wait_for_len(&self, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if self.0.lock().unwrap().len() >= expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}

pub struct ProxyFixture {
    pub controller: NetworkController<EventLog>,
    pub events: EventLog,
}

impl ProxyFixture {
    pub async fn start() -> Self {
        let events = EventLog::default();
        let controller = NetworkController::start(
            NetworkConfig::default(),
            NetworkRunContext::new("sandbox-1", "run-1"),
            events.clone(),
        )
        .await
        .unwrap();
        Self { controller, events }
    }
}

#[derive(Clone)]
pub struct TestConnectRequest {
    pub protocol_version: u16,
    pub token: String,
    pub sandbox_id: String,
    pub run_id: String,
    pub connection_id: String,
    pub destination: SocketAddr,
}

impl TestConnectRequest {
    pub fn new(runtime: &NetworkRuntime, destination: SocketAddr, connection_id: &str) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            token: runtime.token().to_string(),
            sandbox_id: "sandbox-1".to_string(),
            run_id: "run-1".to_string(),
            connection_id: connection_id.to_string(),
            destination,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let authority = self.destination.to_string();
        let executable = "/tmp/test-client"
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!(
            "CONNECT {authority} HTTP/1.1\r\n\
             Host: {authority}\r\n\
             Proxy-Authorization: Bearer {}\r\n\
             Agora-Version: {}\r\n\
             Agora-Sandbox-Id: {}\r\n\
             Agora-Run-Id: {}\r\n\
             Agora-Connection-Id: {}\r\n\
             Agora-Pid: {}\r\n\
             Agora-Ppid: 1\r\n\
             Agora-Operation: connect\r\n\
             Agora-Executable-Hex: {executable}\r\n\
             \r\n",
            self.token,
            self.protocol_version,
            self.sandbox_id,
            self.run_id,
            self.connection_id,
            std::process::id(),
        )
        .into_bytes()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TestProxyResponse {
    pub status: u16,
}

pub async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0_u8; 64];
        loop {
            let read = stream.read(&mut bytes).await.unwrap();
            if read == 0 {
                break;
            }
            stream.write_all(&bytes[..read]).await.unwrap();
        }
    });
    address
}

pub async fn open_tunnel(
    runtime: &NetworkRuntime,
    request: &TestConnectRequest,
) -> (TcpStream, TestProxyResponse) {
    let mut stream = TcpStream::connect(runtime.proxy_ipv4()).await.unwrap();
    stream.write_all(&request.encode()).await.unwrap();
    let response = read_response(&mut stream).await;
    (stream, response)
}

pub async fn send_coverage_gap(
    runtime: &NetworkRuntime,
    destination: SocketAddr,
) -> TestProxyResponse {
    let body = serde_json::to_vec(&json!({
        "protocol_version": PROTOCOL_VERSION,
        "token": runtime.token(),
        "sandbox_id": "sandbox-1",
        "run_id": "run-1",
        "connection_id": "connection-gap",
        "destination": destination,
        "process": {
            "pid": std::process::id(),
            "ppid": 1,
            "executable": "/tmp/test-client"
        },
        "operation": "connect",
        "reason": "unsupported connectx options",
        "fallback": "fail_open"
    }))
    .unwrap();
    let request = format!(
        "POST /_agora/coverage-gap HTTP/1.1\r\n\
         Host: agora-sandbox\r\n\
         Proxy-Authorization: Bearer {}\r\n\
         Agora-Version: {PROTOCOL_VERSION}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        runtime.token(),
        body.len(),
    );
    let mut stream = TcpStream::connect(runtime.proxy_ipv4()).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    read_response(&mut stream).await
}

async fn read_response(stream: &mut TcpStream) -> TestProxyResponse {
    let mut head = Vec::with_capacity(256);
    while head.len() < MAX_FRAME_SIZE {
        let mut byte = 0_u8;
        stream
            .read_exact(std::slice::from_mut(&mut byte))
            .await
            .unwrap();
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            let status = std::str::from_utf8(&head)
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            return TestProxyResponse { status };
        }
    }
    panic!("proxy response exceeded frame limit");
}
