use uuid::Uuid;

pub(crate) const TRACE_IDS_ENVIRONMENT: &str = "AGORA_SANDBOX_TRACE_IDS";
pub(crate) const TRACE_IDS_HEADER: &str = "Agora-Trace-Ids";
const MAX_TRACE_IDS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TraceContext {
    ids: Vec<String>,
}

impl TraceContext {
    pub(crate) fn root() -> Self {
        Self {
            ids: vec![Uuid::new_v4().to_string()],
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        let ids = value
            .split(',')
            .map(str::trim)
            .map(str::to_string)
            .collect::<Vec<_>>();
        Self::new(ids)
    }

    pub(crate) fn new(ids: Vec<String>) -> Result<Self, String> {
        if ids.is_empty() || ids.len() > MAX_TRACE_IDS {
            return Err(format!(
                "trace id chain must contain between 1 and {MAX_TRACE_IDS} entries"
            ));
        }
        if ids.iter().any(|id| !Self::valid_id(id)) {
            return Err("trace id chain contains an invalid entry".to_string());
        }
        Ok(Self { ids })
    }

    pub(crate) fn child(&self) -> Self {
        let mut ids = self.ids.clone();
        if ids.len() == MAX_TRACE_IDS {
            ids.remove(0);
        }
        ids.push(Uuid::new_v4().to_string());
        Self { ids }
    }

    pub(crate) fn ids(&self) -> &[String] {
        &self.ids
    }

    pub(crate) fn encode(&self) -> String {
        self.ids.join(", ")
    }

    fn valid_id(id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 128
            && id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
            })
    }
}

#[cfg(test)]
mod tests;
