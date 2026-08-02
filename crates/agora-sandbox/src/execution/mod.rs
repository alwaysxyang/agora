mod controller;
mod protocol;
mod store;

pub(crate) use controller::ExecutionController;
#[cfg(test)]
pub(crate) use protocol::{EXECUTION_PROTOCOL_VERSION, decode_prepare_request};
pub(crate) use protocol::{
    PrepareResponse, decode_prepare_response, encode_prepare_request, frame_length,
};
pub(crate) use store::{resolve_executable, resolve_shebang};

#[cfg(test)]
mod tests;
