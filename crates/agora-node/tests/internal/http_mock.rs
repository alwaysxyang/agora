use std::io;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, timeout_at};

const MAX_REQUEST_SIZE: usize = 1024 * 1024;
const WAIT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub(super) struct RecordedRequest {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) body: String,
}

impl RecordedRequest {
    pub(super) fn endpoint(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
pub(super) struct MockResponse {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
}

impl MockResponse {
    pub(super) fn json(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into().into_bytes(),
            content_type: "application/json",
        }
    }
}

type ResponseHandler = dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync;

pub(super) struct HttpMockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    request_count: watch::Receiver<usize>,
    errors: Arc<StdMutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl HttpMockServer {
    pub(super) async fn start(
        handler: impl Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let (request_count_tx, request_count) = watch::channel(0);
        let errors = Arc::new(StdMutex::new(Vec::new()));
        let captured_errors = Arc::clone(&errors);
        let handler: Arc<ResponseHandler> = Arc::new(handler);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let captured = Arc::clone(&captured);
                        let request_count_tx = request_count_tx.clone();
                        let handler = Arc::clone(&handler);
                        connections.spawn(async move {
                            let mut stream = stream;
                            let request = read_request(&mut stream).await?;
                            let response = handler(&request);
                            let mut requests = captured.lock().await;
                            requests.push(request);
                            request_count_tx.send_replace(requests.len());
                            drop(requests);
                            write_response(&mut stream, response).await
                        });
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        let error = match result {
                            Ok(Ok(())) => continue,
                            Ok(Err(error)) => error.to_string(),
                            Err(error) => error.to_string(),
                        };
                        captured_errors.lock().unwrap().push(error);
                    }
                }
            }
        });
        Self {
            base_url,
            requests,
            request_count,
            errors,
            task,
        }
    }

    pub(super) async fn start_json_queue<const N: usize>(responses: [&str; N]) -> Self {
        let responses = StdMutex::new(
            responses
                .into_iter()
                .map(str::to_string)
                .collect::<std::collections::VecDeque<_>>(),
        );
        Self::start(move |_| {
            let body = responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("mock response queue exhausted");
            MockResponse::json(body)
        })
        .await
    }

    pub(super) fn base_url(&self) -> String {
        self.base_url.clone()
    }

    pub(super) async fn requests(&self) -> Vec<RecordedRequest> {
        self.assert_healthy();
        self.requests.lock().await.clone()
    }

    pub(super) async fn endpoint_count(&self, endpoint: &str) -> usize {
        self.requests
            .lock()
            .await
            .iter()
            .filter(|request| request.endpoint() == endpoint)
            .count()
    }

    pub(super) async fn wait_for_method_count(&self, method: &str, expected: usize) {
        self.wait_for(|requests| {
            requests
                .iter()
                .filter(|request| request.method == method)
                .count()
                >= expected
        })
        .await;
    }

    pub(super) async fn wait_for_endpoint_count(&self, endpoint: &str, expected: usize) {
        self.wait_for(|requests| {
            requests
                .iter()
                .filter(|request| request.endpoint() == endpoint)
                .count()
                >= expected
        })
        .await;
    }

    pub(super) async fn wait_for(&self, predicate: impl Fn(&[RecordedRequest]) -> bool) {
        let deadline = Instant::now() + WAIT_TIMEOUT;
        let mut request_count = self.request_count.clone();
        loop {
            self.assert_healthy();
            if predicate(&self.requests.lock().await) {
                return;
            }
            timeout_at(deadline, request_count.changed())
                .await
                .expect("timed out waiting for mock HTTP request")
                .expect("mock HTTP server stopped before receiving the expected request");
        }
    }

    fn assert_healthy(&self) {
        let errors = self.errors.lock().unwrap();
        assert!(errors.is_empty(), "mock HTTP server errors: {errors:?}");
    }
}

impl Drop for HttpMockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(stream: &mut TcpStream) -> io::Result<RecordedRequest> {
    let mut received = Vec::with_capacity(4096);
    let header_end = loop {
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before sending a complete HTTP request",
            ));
        }
        received.extend_from_slice(&buffer[..read]);
        if received.len() > MAX_REQUEST_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mock HTTP request exceeded size limit",
            ));
        }
        if let Some(index) = find_bytes(&received, b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&received[..header_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .to_string();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .unwrap_or_default();
    if header_end.saturating_add(content_length) > MAX_REQUEST_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mock HTTP request exceeded size limit",
        ));
    }
    while received.len() < header_end + content_length {
        let mut buffer = [0_u8; 4096];
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before sending the complete HTTP body",
            ));
        }
        received.extend_from_slice(&buffer[..read]);
    }
    let mut request_line = headers
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();
    if method.is_empty() || path.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mock HTTP request line was invalid",
        ));
    }
    let body = String::from_utf8(received[header_end..header_end + content_length].to_vec())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(RecordedRequest { method, path, body })
}

async fn write_response(stream: &mut TcpStream, response: MockResponse) -> io::Result<()> {
    let reason = if response.status == 200 {
        "OK"
    } else {
        "Error"
    };
    let head = format!(
        "HTTP/1.1 {} {reason}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
