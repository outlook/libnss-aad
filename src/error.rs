
extern crate hyper;
extern crate serde_json;
extern crate url;

use std;

pub type PasswdBufferFillResult<T> = Result<T, PasswdBufferFillError>;

#[derive(Debug)]
pub enum PasswdBufferFillError {
    InsufficientBuffer,
    NullPointerError,
    ZeroByteInString
}

impl From<std::ffi::NulError> for PasswdBufferFillError {
    fn from(_: std::ffi::NulError) -> PasswdBufferFillError {
        PasswdBufferFillError::ZeroByteInString
    }
}

pub type UserInfoResult<T> = Result<T, UserInfoRetrievalError>;

#[derive(Debug)]
pub enum UserInfoRetrievalError {
    NoAccessToken { response: String },
    BadHTTPResponse { status: hyper::status::StatusCode },
    BadJSONResponse,
    HTTPError(hyper::error::Error),
    UnusableImmutableID
}

impl From<serde_json::Error> for UserInfoRetrievalError {
    fn from(_: serde_json::Error) -> UserInfoRetrievalError {
        UserInfoRetrievalError::BadJSONResponse
    }
}

impl From<hyper::error::Error> for UserInfoRetrievalError {
    fn from(err: hyper::error::Error) -> UserInfoRetrievalError {
        UserInfoRetrievalError::HTTPError(err)
    }
}

impl From<std::io::Error> for UserInfoRetrievalError {
    fn from(err: std::io::Error) -> UserInfoRetrievalError {
        UserInfoRetrievalError::HTTPError(hyper::error::Error::Io(err))  // heh.
    }
}

impl From<std::num::ParseIntError> for UserInfoRetrievalError {
    fn from(_: std::num::ParseIntError) -> UserInfoRetrievalError {
        UserInfoRetrievalError::UnusableImmutableID
    }
}
