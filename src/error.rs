
extern crate hyper;
extern crate serde_json;
extern crate url;

use std;

pub type BufferFillResult<T> = Result<T, BufferFillError>;

#[derive(Debug)]
pub enum BufferFillError {
    InsufficientBuffer,
    NullPointerError,
    ZeroByteInString
}

impl From<std::ffi::NulError> for BufferFillError {
    fn from(_: std::ffi::NulError) -> BufferFillError {
        BufferFillError::ZeroByteInString
    }
}

pub type GraphInfoResult<T> = Result<T, GraphInfoRetrievalError>;

#[derive(Debug)]
pub enum GraphInfoRetrievalError {
    NoAccessToken { response: String },
    BadHTTPResponse { status: hyper::status::StatusCode, data: String },
    BadJSONResponse,
    HTTPError(hyper::error::Error),
    UnusableImmutableID,
    TooManyResults,
    NotFound
}

impl From<serde_json::Error> for GraphInfoRetrievalError {
    fn from(_: serde_json::Error) -> GraphInfoRetrievalError {
        GraphInfoRetrievalError::BadJSONResponse
    }
}

impl From<hyper::error::Error> for GraphInfoRetrievalError {
    fn from(err: hyper::error::Error) -> GraphInfoRetrievalError {
        GraphInfoRetrievalError::HTTPError(err)
    }
}

impl From<std::io::Error> for GraphInfoRetrievalError {
    fn from(err: std::io::Error) -> GraphInfoRetrievalError {
        GraphInfoRetrievalError::HTTPError(hyper::error::Error::Io(err))  // heh.
    }
}

impl From<std::num::ParseIntError> for GraphInfoRetrievalError {
    fn from(_: std::num::ParseIntError) -> GraphInfoRetrievalError {
        GraphInfoRetrievalError::UnusableImmutableID
    }
}
