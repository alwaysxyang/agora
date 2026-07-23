use crate::protocol::RouteRegistration;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub(super) struct RegisteredRoute {
    pub(super) registration: RouteRegistration,
    pub(super) upstream: TcpStream,
    registered_at: Instant,
}

pub(super) struct RouteRegistry {
    ttl: Duration,
    routes: Mutex<HashMap<SocketAddr, RegisteredRoute>>,
}

impl RouteRegistry {
    pub(super) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            routes: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn insert(
        &self,
        registration: RouteRegistration,
        upstream: TcpStream,
    ) -> io::Result<()> {
        let now = Instant::now();
        let mut routes = self.routes();
        routes.retain(|_, route| now.duration_since(route.registered_at) <= self.ttl);
        if routes.contains_key(&registration.source) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("route for {} is already registered", registration.source),
            ));
        }
        routes.insert(
            registration.source,
            RegisteredRoute {
                registration,
                upstream,
                registered_at: now,
            },
        );
        Ok(())
    }

    pub(super) fn take(&self, source: SocketAddr) -> Option<RegisteredRoute> {
        let route = self.routes().remove(&source)?;
        if route.registered_at.elapsed() > self.ttl {
            return None;
        }
        Some(route)
    }

    fn routes(&self) -> MutexGuard<'_, HashMap<SocketAddr, RegisteredRoute>> {
        self.routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
