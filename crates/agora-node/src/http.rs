use crate::config::HttpProxy;
use anyhow::{Context, Result, bail};
use reqwest::{Client, ClientBuilder, Response};

pub(crate) const MAX_TASK_ATTACHMENT_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn client(builder: ClientBuilder, proxy: Option<&HttpProxy>) -> Result<Client> {
    let builder = match proxy {
        Some(proxy) => {
            let mut configured = reqwest::Proxy::all(format!("http://{}", proxy.address()))
                .context("configure HTTP proxy failed")?;
            if let Some((username, password)) = proxy.credentials() {
                configured = configured.basic_auth(username, password);
            }
            builder.proxy(configured)
        }
        None => builder,
    };
    #[cfg(test)]
    let builder = if proxy.is_none() {
        builder.no_proxy()
    } else {
        builder
    };
    builder.build().context("build HTTP client failed")
}

pub(crate) async fn read_body_limited(mut response: Response, maximum: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        bail!("HTTP response body limit exceeded: maximum {maximum} bytes");
    }
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or_default()
        .min(maximum);
    let mut data = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("HTTP response body read failed"))?
    {
        if chunk.len() > maximum.saturating_sub(data.len()) {
            bail!("HTTP response body limit exceeded: maximum {maximum} bytes");
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}
