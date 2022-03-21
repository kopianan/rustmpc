pub mod party_i;

#[derive(Clone, Debug)]
pub struct ErrorType {
    error_type: String,
    bad_actors: Vec<usize>,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
    Phase5BadSum,
    Phase6Error,
}