mod controller;
mod protocol;
mod store;

pub(crate) use controller::ExecutionController;
#[cfg(test)]
pub(crate) use protocol::decode_prepare_request;
pub(crate) use protocol::{
    CommandRequest, PrepareResponse, ProcessOperation, decode_prepare_response,
    encode_prepare_request, encode_prepare_request_with_command, frame_length,
};
pub(crate) use store::{resolve_executable, resolve_shebang};

#[cfg(test)]
mod tests;
