use crate::config::HttpProxy;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_CONNECT_RESPONSE_SIZE: usize = 8192;

pub(super) async fn connect_tunnel(proxy: &HttpProxy, target_url: &str) -> Result<TcpStream> {
    let target = reqwest::Url::parse(target_url).context("parse websocket URL failed")?;
    let host = target
        .host_str()
        .ok_or_else(|| anyhow!("websocket URL is missing a host"))?;
    let port = target
        .port_or_known_default()
        .ok_or_else(|| anyhow!("websocket URL is missing a port"))?;
    let authority = if host.starts_with('[') && host.ends_with(']') {
        format!("{host}:{port}")
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let mut stream = TcpStream::connect(proxy.address())
        .await
        .context("connect HTTP proxy failed")?;
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((username, password)) = proxy.credentials() {
        let credentials = STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("write HTTP proxy CONNECT request failed")?;

    let mut response = Vec::with_capacity(512);
    let header_end = loop {
        let mut buffer = [0_u8; 512];
        let read = stream
            .read(&mut buffer)
            .await
            .context("read HTTP proxy CONNECT response failed")?;
        if read == 0 {
            bail!("HTTP proxy closed before completing CONNECT");
        }
        response.extend_from_slice(&buffer[..read]);
        if response.len() > MAX_CONNECT_RESPONSE_SIZE {
            bail!("HTTP proxy CONNECT response is too large");
        }
        if let Some(index) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let status = std::str::from_utf8(&response[..header_end])
        .context("HTTP proxy CONNECT response is not valid UTF-8")?
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("HTTP proxy CONNECT response is invalid"))?;
    if !(200..300).contains(&status) {
        bail!("HTTP proxy CONNECT failed with status {status}");
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    async fn test_proxy(response: Vec<u8>) -> (HttpProxy, oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().to_string().parse().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let mut buffer = [0_u8; 512];
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let _ = request_tx.send(String::from_utf8(request).unwrap());
            if !response.is_empty() {
                stream.write_all(&response).await.unwrap();
            }
        });
        (proxy, request_rx)
    }

    #[tokio::test]
    async fn tunnel_sends_connect_and_optional_basic_auth() {
        let (proxy, request) = test_proxy(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()).await;
        let proxy = format!("user:password@{}", proxy.address())
            .parse()
            .unwrap();

        connect_tunnel(&proxy, "wss://[::1]:9443/callback")
            .await
            .unwrap();

        let request = request.await.unwrap();
        assert!(request.starts_with("CONNECT [::1]:9443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: [::1]:9443\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n"));

        let (proxy, request) = test_proxy(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()).await;
        connect_tunnel(&proxy, "ws://example.test/path")
            .await
            .unwrap();
        assert!(!request.await.unwrap().contains("Proxy-Authorization"));
    }

    #[tokio::test]
    async fn tunnel_reports_invalid_targets_and_proxy_responses() {
        let proxy: HttpProxy = "127.0.0.1:1".parse().unwrap();
        assert!(connect_tunnel(&proxy, "not a URL").await.is_err());
        assert!(
            connect_tunnel(&proxy, "file:///tmp/socket")
                .await
                .unwrap_err()
                .to_string()
                .contains("host")
        );
        assert!(
            connect_tunnel(&proxy, "custom://example.test/path")
                .await
                .unwrap_err()
                .to_string()
                .contains("port")
        );

        for (response, expected) in [
            (Vec::new(), "closed"),
            (vec![b'a'; MAX_CONNECT_RESPONSE_SIZE + 1], "too large"),
            (b"HTTP/1.1 \xff\r\n\r\n".to_vec(), "UTF-8"),
            (b"invalid\r\n\r\n".to_vec(), "invalid"),
            (
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".to_vec(),
                "status 407",
            ),
        ] {
            let (proxy, _) = test_proxy(response).await;
            let error = connect_tunnel(&proxy, "wss://example.test/socket")
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error:#}"
            );
        }
    }
}
