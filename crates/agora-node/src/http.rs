use crate::config::HttpProxy;
use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder};

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
