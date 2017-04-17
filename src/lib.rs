extern crate libc;

#[macro_use]
extern crate serde_derive;

extern crate hyper;
extern crate serde_yaml;

mod azure;
mod error;

use error::{UserInfoRetrievalError, PasswdBufferFillError, PasswdBufferFillResult};
use hyper::status::StatusCode;
use libc::{c_char, uid_t, gid_t, size_t, passwd};
use libc::{ENOENT, EAGAIN, ERANGE};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::prelude::*;
use std::ptr::copy_nonoverlapping;

enum NssStatus {
    NssStatusTryagain = -2,
    NssStatusUnavail,
    NssStatusNotfound,
    NssStatusSuccess
        // NssStatusReturn exists in passwd.h but is not used here
}

#[derive(Deserialize,Debug)]
pub struct AadConfig {
    client_id: String,
    client_secret: String,
    tenant: String
}

impl AadConfig {
    fn from_file(filename: &str) -> serde_yaml::Result<AadConfig> {
        let mut file = File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        serde_yaml::from_str(&contents)
    }
}

pub struct UserInfo {
    username: String,
    fullname: String,
    userid: u32 // too platform-specific? should this be something else?
}

#[no_mangle]
pub extern fn _nss_aad_getpwnam_r(name: *const c_char, pw: *mut passwd, buffer: *mut c_char, buflen: size_t, errnop: *mut i32) -> i32 {

    let name: &CStr = unsafe {assert!(!name.is_null()); CStr::from_ptr(name) };
    let name: &str = match name.to_str() {
        Ok(s) => s,
        Err(_) => { return nss_entry_not_available(errnop); }
    };

    let config = match AadConfig::from_file("/etc/nssaad.conf") {
        Ok(c) => c,
        Err(_) => { return nss_input_file_err(errnop); }
    };

    let userinfo = match azure::get_user_info(config, name) {
        Ok(i) => i,
        Err(e) => {
            match e {
                UserInfoRetrievalError::BadHTTPResponse{status} => {
                    match status {
                        StatusCode::NotFound => { return nss_entry_not_available(errnop); },
                            _ => { return nss_out_of_service(errnop); }
                    }
                },
                _ => { return nss_out_of_service(errnop); }
            };
        }
    };

    unsafe {
        (*pw).pw_uid = userinfo.userid as uid_t;
        (*pw).pw_gid = userinfo.userid as gid_t;
    }

    match fill_buffer(pw, buffer, buflen, userinfo.username, userinfo.fullname) {
        Ok(()) => NssStatus::NssStatusSuccess as i32,
        Err(e) => match e {
            PasswdBufferFillError::ZeroByteInString => nss_entry_not_available(errnop),
            _ => nss_insufficient_buffer(errnop)
        }
    }
}

fn fill_buffer(pw: *mut passwd, buffer: *mut c_char, buflen: size_t, username: String, fullname: String) -> PasswdBufferFillResult<()> {
    if pw.is_null() || buffer.is_null() || buflen == 0 {
        return Err(PasswdBufferFillError::NullPointerError);
    }
    let c_name = CString::new(username.clone())?.into_bytes_with_nul();
    let c_passwd = CString::new("*")?.into_bytes_with_nul();
    let c_gecos = CString::new(fullname)?.into_bytes_with_nul();
    let c_dir = CString::new(format!("/home/{}", username))?.into_bytes_with_nul();
    let c_shell = CString::new("/bin/bash")?.into_bytes_with_nul();

    if buflen < c_name.len() + c_passwd.len() + c_gecos.len() + c_dir.len() + c_shell.len() {
        return Err(PasswdBufferFillError::InsufficientBuffer);
    }

    let mut buf_cur = buffer;
    unsafe {
        copy_nonoverlapping(c_name.as_ptr(), buf_cur as *mut u8, c_name.len());
        (*pw).pw_name = buf_cur;
        buf_cur = buf_cur.offset(c_name.len() as isize);

        copy_nonoverlapping(c_passwd.as_ptr(), buf_cur as *mut u8, c_passwd.len());
        (*pw).pw_passwd = buf_cur;
        buf_cur = buf_cur.offset(c_passwd.len() as isize);

        copy_nonoverlapping(c_gecos.as_ptr(), buf_cur as *mut u8, c_gecos.len());
        (*pw).pw_gecos = buf_cur;
        buf_cur = buf_cur.offset(c_gecos.len() as isize);

        copy_nonoverlapping(c_shell.as_ptr(), buf_cur as *mut u8, c_shell.len());
        (*pw).pw_shell = buf_cur;
        buf_cur = buf_cur.offset(c_shell.len() as isize);

        copy_nonoverlapping(c_dir.as_ptr(), buf_cur as *mut u8, c_dir.len());
        (*pw).pw_dir = buf_cur;
    }

    Ok(())
}

fn nss_out_of_service(errnop: *mut i32) -> i32 {
    unsafe { *errnop = EAGAIN };
    NssStatus::NssStatusTryagain as i32
}

fn nss_insufficient_buffer(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ERANGE };
    NssStatus::NssStatusTryagain as i32
}

fn nss_input_file_err(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ENOENT };
    NssStatus::NssStatusUnavail as i32
}

fn nss_entry_not_available(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ENOENT };
    NssStatus::NssStatusNotfound as i32
}

fn nss_no_entries_available(errnop: *mut i32) -> i32 {
    unsafe { *errnop = 0 };
    NssStatus::NssStatusNotfound as i32
}


/*

// Kept in case it's useful in the future.

struct MaxUidExceeded;

fn get_next_uid() -> Result<u32, MaxUidExceeded> {
    let mut uid: u32 = 1000;
    loop {
        unsafe {
            let p = libc::getpwuid(uid as uid_t);
            if p.is_null() {
                let g = libc::getgrgid(uid as gid_t);
                if g.is_null() {
                    break;
                }
            }
            uid += 1;
            if uid > 65000 {
                return Err(MaxUidExceeded);
            }
        }
    }
    Ok(uid)
}
*/
