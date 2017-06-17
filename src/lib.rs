//! libnss-aad is a glibc NSS plugin that queries Azure Active Directory for information
//!
//! The public functions in this library do not form a comprehensive implementation of an
//! NSS plugin, but only provide the minimum necessary for the author's use cases.

extern crate core;
extern crate libc;

#[macro_use]
extern crate serde_derive;

extern crate hyper;
extern crate serde_yaml;

mod azure;
mod error;

use core::ptr::null_mut;
use error::{GraphInfoRetrievalError, BufferFillError, BufferFillResult};
use hyper::status::StatusCode;
use libc::{c_void, c_char, uid_t, gid_t, size_t, passwd, group};
use libc::{ENOENT, EAGAIN, ERANGE};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::prelude::*;
use std::ptr::copy_nonoverlapping;

/// NssStatus is the return value from libnss-called functions; they are cast to i32 when being
/// returned.
enum NssStatus {
    TryAgain = -2,
    Unavailable,
    NotFound,
    Success, // NssStatusReturn exists in passwd.h but is not used here
}

#[derive(Deserialize,Debug)]
pub struct AadConfig {
    client_id: String,
    client_secret: String,
    domain_sid: String,
    default_user_group_id: u32,
    tenant: String,
    group_ids: HashMap<String, gid_t>,
}

impl AadConfig {
    /// Helper function to initialize an AadConfig from the named file.
    fn from_file(filename: &str) -> serde_yaml::Result<AadConfig> {
        let mut file = File::open(filename)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        serde_yaml::from_str(&contents)
    }
}

#[derive(Debug)]
pub struct UserInfo {
    username: String,
    fullname: String,
    userid: u32, // too platform-specific? should this be something else?
}

#[derive(Debug)]
pub struct GroupInfo {
    groupname: String,
    object_id: String,
    group_id: u32
}

/// The initgroups_dyn function populates a list of GIDs to which the named user belongs.
///
/// This function is very sparsely documented, and does not appear to be part of the typical
/// set of expected functions implemented by a libnss plugin. I do not know why. The following
/// argument descriptions come from the libnss-ldap package:
///
///   name      IN     - the user name to find groups for
///   skipgroup IN     - a group to not include in the list
///   *start    IN/OUT - where to write in the array, is incremented
///   *size     IN/OUT - the size of the supplied array (gid_t entries, not bytes)
///   **groupsp IN/OUT - pointer to the array of returned groupids
///   limit     IN     - the maxium size of the array
///   *errnop   OUT    - for returning errno
#[no_mangle]
pub extern "C" fn _nss_aad_initgroups_dyn(name: *const c_char,
                                          skipgroup: gid_t,
                                          start: *mut size_t,
                                          size: *mut size_t,
                                          mut groupsp: *mut *mut gid_t,
                                          limit: size_t,
                                          errnop: *mut i32)
                                          -> i32 {

    assert!(!groupsp.is_null() && !name.is_null() && !start.is_null() && !size.is_null());

    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return nss_entry_not_available(errnop);
        }
    };
    #[cfg(debug_assertions)]
    println!("libnss-aad initgroups_dyn called for {}", name);

    let config = match AadConfig::from_file("/etc/nssaad.conf") {
        Ok(c) => c,
        Err(_) => {
            return nss_input_file_err(errnop);
        }
    };

    // Get the user's groups, keeping the GIDs of only those groups appearing in the config file,
    // and that are not equal to `skipgroup`.
    let user_groups: Vec<gid_t> = match azure::get_user_groups(&config, name) {
            Ok(v) => v,
            Err(err) => {
            #[cfg(debug_assertions)]
                println!("libnss-aad failed to get user groups: {:?}", err);
                return nss_entry_not_available(errnop);
            }
        }
        .iter()
        .filter_map(|g| config.group_ids.get(&g.groupname))
        .cloned()
        .filter(|&gid| gid != skipgroup)
        .collect();

    // If we get no groups, then we have nothing to do.
    if user_groups.is_empty() {
        #[cfg(debug_assertions)]
        println!("libnss-aad got no user groups for {}", name);
        return NssStatus::Success as i32;
    }

    // How big is the array we were passed, and how deep into it are we?
    let mut idx = unsafe { *start };
    let mut group_arraysz = unsafe { *size };
    #[cfg(debug_assertions)]
    println!("libnss-aad group array size={}@idx {}, adding {}",
             group_arraysz,
             idx,
             user_groups.len());
    if idx + user_groups.len() > group_arraysz {
        // We need to add more group IDs to the array than we currently have space for
        let new_sz = std::cmp::min(idx + user_groups.len(), limit);
        unsafe {
            *groupsp = libc::realloc(*groupsp as *mut c_void, new_sz) as *mut gid_t;
            *size = new_sz;
        }
        group_arraysz = new_sz;
    }

    // Now that we've got the memory we need, build a raw slice into which we can copy values out
    // of the Rust user_groups Vec.
    let group_array: &mut [gid_t] =
        unsafe { std::slice::from_raw_parts_mut(*groupsp, group_arraysz) };

    for gid in user_groups {
        // Copy the GID into the raw slice
        group_array[idx] = gid;
        // keeping track of the index (which must be returned to the caller)
        idx += 1;
        if idx == limit {
            // if we run out of space, bail
            break;
        }
    }

    unsafe {
        *start = idx; // Lets future users of this memory know where free space begins
    }

    NssStatus::Success as i32
}


/// The `getgrnam` function retrieves group information about the named group
///
/// The `result` argument is a pointer to an already-allocated C struct group, which consists
/// of member pointers. The information that is looked up is stored in `buffer`, and `result`'s
/// pointers point into the buffer.
///
/// The group's GID is looked up in the configuration.
#[no_mangle]
pub extern "C" fn _nss_aad_getgrnam_r(name: *const c_char,
                                      result: *mut group,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());

    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return nss_entry_not_available(errnop);
        }
    };
    #[cfg(debug_assertions)]
    println!("libnss-aad getgrnam_r called for {}", name);

    let config = match AadConfig::from_file("/etc/nssaad.conf") {
        Ok(c) => c,
        Err(_) => {
            return nss_input_file_err(errnop);
        }
    };

    // Get the attributes of the group. Specifically we need its object ID.
    let groupinfo = match azure::get_group_info(&config, name) {
        Ok(i) => i,
        Err(e) => {
            match e {
                GraphInfoRetrievalError::BadHTTPResponse { status, .. } => {
                    match status {
                        StatusCode::NotFound => {
                            #[cfg(debug_assertion)]
                            println!("libnss-aad getgrnam could not find {}", name);
                            return nss_entry_not_available(errnop);
                        }
                        _ => {
                            return nss_out_of_service(errnop);
                        }
                    }
                }
                GraphInfoRetrievalError::TooManyResults |
                GraphInfoRetrievalError::NotFound => {
                    return nss_entry_not_available(errnop);
                }
                _ => {
                    return nss_out_of_service(errnop);
                }
            };
        }
    };

    // Look up members of the group, using the group's object ID
    let groupmembers: Vec<UserInfo> = match azure::get_group_members(&config,
                                                                     &groupinfo.object_id) {
        Ok(m) => m,
        _ => vec![],
    };

    match fill_group_buf(result,
                         groupinfo.group_id as gid_t,
                         buffer,
                         buflen,
                         name,
                         &groupmembers) {
        Ok(()) => NssStatus::Success as i32,
        Err(e) => {
            match e {
                BufferFillError::InsufficientBuffer => nss_insufficient_buffer(errnop),
                _ => {
                #[cfg(debug_assertions)]
                    println!("libnss-aad getgrnam_r failed because {:?}", e);
                    nss_entry_not_available(errnop)
                }
            }
        }
    }
}

/// This function accepts Rust structures and copies their contents into the buffer provided to
/// store the contents of the provided C struct group.
///
/// This function does no allocation/reallocation. If there is not enough buffer space to store
/// everything, the function returns and relies upon the NSS caller to reallocate.
///
/// This function _does not_ expose any Rust structures to C, but instead performs bytewise
/// nonoverlapping copies into `buffer`.
///
/// Modifies `grp` and `buffer`.
fn fill_group_buf(grp: *mut group,
                  gid: gid_t,
                  buffer: *mut c_char,
                  buflen: size_t,
                  name: &str,
                  members: &[UserInfo])
                  -> BufferFillResult<()> {
    #[cfg(debug_assertion)]
    println!("filling group buffer for group {} which has {} members",
             name,
             members.len());

    // name and passwd are easy - we can copy them straight into the provided buffer
    let c_name = CString::new(name)?.into_bytes_with_nul();
    let c_gpasswd = CString::new("!")?.into_bytes_with_nul();

    // members are harder - we need to provide a pointer to the base of a vector of pointers
    // c_members is a vector of names (which are themselves vectors of bytes)
    let c_members = members
        .iter()
        .map(|m: &UserInfo| {
                 let c_member = CString::new(m.username.clone()).unwrap();
                 c_member.into_bytes_with_nul()
             })
        .collect::<Vec<Vec<u8>>>();
    let memberlen = c_members.iter().fold(0, |acc, m| acc + m.len());

    // if buffer isn't long enough to hold all the names, bail accordingly
    if buflen < c_name.len() + c_gpasswd.len() + memberlen {
        return Err(BufferFillError::InsufficientBuffer);
    }

    // here is our vector of pointers. these will point to member names copied into the buffer,
    // and grp.gr_mem will point at it.
    let mut c_member_ptrs: Vec<*mut c_char> = Vec::with_capacity(c_members.len() + 1);

    // Our cursor into the buffer
    let mut buf_cur = buffer;

    unsafe {
        // First, the easy ones. Copy the name and passwd files into the buffer, setting
        // grp member pointers accordingly.
        copy_nonoverlapping(c_name.as_ptr(), buf_cur as *mut u8, c_name.len());
        (*grp).gr_name = buf_cur;
        buf_cur = buf_cur.offset(c_name.len() as isize);
        copy_nonoverlapping(c_gpasswd.as_ptr(), buf_cur as *mut u8, c_gpasswd.len());
        (*grp).gr_passwd = buf_cur;
        buf_cur = buf_cur.offset(c_gpasswd.len() as isize);
    }

    // Now the harder stuff.

    // for each nul-terminated vector of bytes (member name) in the vector of vectors
    for c_member in c_members {
        // first, copy the member name vector's bytes into the buffer
        unsafe {
            copy_nonoverlapping(c_member.as_ptr(), buf_cur as *mut u8, c_member.len());
        }
        // then store the location (in the buffer) in our vector of pointers
        c_member_ptrs.push(buf_cur);
        // and move the cursor
        unsafe {
            buf_cur = buf_cur.offset(c_member.len() as isize);
        }
    }
    // the last item in the vector of pointers should be a null pointer
    c_member_ptrs.push(null_mut());

    let c_ptr_array_sz = c_member_ptrs.len() * std::mem::size_of::<*mut c_char>();
    unsafe {
        // Because glibc will presumably use libc to free() the array of names, we have to use
        // libc to malloc it, too.
        let c_ptr_array: *mut *mut c_char = libc::malloc(c_ptr_array_sz) as *mut *mut c_char;
        // Now, copy the pointers into the newly-allocated space
        copy_nonoverlapping(c_member_ptrs.as_ptr(), c_ptr_array, c_member_ptrs.len());
        // then store the location of our array
        (*grp).gr_mem = c_ptr_array;
    }

    // copy the gid value into the grp object
    unsafe {
        (*grp).gr_gid = gid;
    }

    Ok(())
}

/// getgrgid returns information about the group identified by the provided GID
///
/// The `result` argument is a pointer to an already-allocated C struct group, which contains
/// of member pointers. The information that is looked up is stored in `buffer`, and `result`'s
/// pointers point into the buffer.
///
/// The group name is looked up in the configuration. The first matching result is returned (that
/// is, duplicated GIDs are ignored).
#[no_mangle]
pub extern "C" fn _nss_aad_getgrgid_r(gid: gid_t,
                                      result: *mut group,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!result.is_null() && !buffer.is_null() && !errnop.is_null());

    if gid < 1000 {
        return nss_entry_not_available(errnop);
    }

    #[cfg(debug_assertions)]
    println!("libnss-aad getgrgid_r called for {}", gid);

    let config = match AadConfig::from_file("/etc/nssaad.conf") {
        Ok(c) => c,
        Err(_) => {
            return nss_input_file_err(errnop);
        }
    };

    let sid = format!("{}-{}", config.domain_sid, gid);

    // Get the attributes of the group. Specifically we need its object ID.
    let groupinfo = match azure::get_group_info_by_sid(&config, &sid) {
        Ok(i) => i,
        Err(e) => {
            match e {
                GraphInfoRetrievalError::BadHTTPResponse { status, .. } => {
                    match status {
                        StatusCode::NotFound => {
                            #[cfg(debug_assertion)]
                            println!("libnss-aad getgrgid could not find {}", name);
                            return nss_entry_not_available(errnop);
                        }
                        _ => {
                            return nss_out_of_service(errnop);
                        }
                    }
                }
                GraphInfoRetrievalError::TooManyResults |
                GraphInfoRetrievalError::NotFound => {
                    return nss_entry_not_available(errnop);
                }
                _ => {
                    return nss_out_of_service(errnop);
                }
            };
        }
    };

    // Look up members of the group, using the group's object ID
    let groupmembers: Vec<UserInfo> = match azure::get_group_members(&config,
                                                                     &groupinfo.object_id) {
        Ok(m) => m,
        _ => vec![],
    };

    match fill_group_buf(result, gid, buffer, buflen, &groupinfo.groupname, &groupmembers) {
        Ok(()) => NssStatus::Success as i32,
        Err(e) => {
            match e {
                BufferFillError::InsufficientBuffer => nss_insufficient_buffer(errnop),
                _ => {
                    #[cfg(debug_assertions)]
                    println!("libnss-aad getgrgid_r failed because {:?}", e);
                    nss_entry_not_available(errnop)
                }
            }
        }
    }
}


/// getpwuid
#[no_mangle]
pub extern "C" fn _nss_aad_getpwuid_r(uid: uid_t,
                                      pw: *mut passwd,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!pw.is_null() && !buffer.is_null() && !errnop.is_null());

    if uid < 1000 {
        return nss_entry_not_available(errnop);
    }

    #[cfg(debug_assertions)]
    println!("libnss-aad getpwuid_r called for {}", uid);

    let config = match AadConfig::from_file("/etc/nssaad.conf") {
        Ok(c) => c,
        Err(_) => {
            return nss_input_file_err(errnop);
        }
    };

    let sid = format!("{}-{}", config.domain_sid, uid);

    let userinfo = match azure::get_user_info_by_sid(&config, &sid) {
        Ok(i) => i,
        Err(e) => {
            match e {
                GraphInfoRetrievalError::BadHTTPResponse { status, .. } => {
                    match status {
                        StatusCode::NotFound => {
                            #[cfg(debug_assertion)]
                            println!("libnss-aad getpwuid could not find {}", uid);
                            return nss_entry_not_available(errnop);
                        }
                        _ => {
                            return nss_out_of_service(errnop);
                        }
                    }
                }
                GraphInfoRetrievalError::TooManyResults |
                GraphInfoRetrievalError::NotFound => {
                    return nss_entry_not_available(errnop);
                }
                _ => {
                    return nss_out_of_service(errnop);
                }
            };
        }
    };

    unsafe {
        (*pw).pw_uid = userinfo.userid as uid_t;
        (*pw).pw_gid = config.default_user_group_id as gid_t;
    }

    match fill_passwd_buf(pw, buffer, buflen, &userinfo.username, userinfo.fullname) {
        Ok(()) => NssStatus::Success as i32,
        Err(e) => {
            match e {
                BufferFillError::ZeroByteInString => nss_entry_not_available(errnop),
                _ => nss_insufficient_buffer(errnop),
            }
        }
    }
}					

/// getpwnam returns information about the named user
///
/// The `pw` argument is a pointer to an already-allocated C struct passwd, which contains
/// of member pointers. The information that is looked up is stored in `buffer`, and `pw`'s
/// pointers point into the buffer.
#[no_mangle]
pub extern "C" fn _nss_aad_getpwnam_r(name: *const c_char,
                                      pw: *mut passwd,
                                      buffer: *mut c_char,
                                      buflen: size_t,
                                      errnop: *mut i32)
                                      -> i32 {

    assert!(!pw.is_null() && !buffer.is_null() && !errnop.is_null());

    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return nss_entry_not_available(errnop);
        }
    };
    
    #[cfg(debug_assertions)]
    println!("libnss-aad getpwnam_r called for {}", name);

    let config = match AadConfig::from_file("/etc/nssaad.conf") {
        Ok(c) => c,
        Err(_) => {
            return nss_input_file_err(errnop);
        }
    };

    let userinfo = match azure::get_user_info(&config, name) {
        Ok(i) => i,
        Err(e) => {
            match e {
                GraphInfoRetrievalError::BadHTTPResponse { status, .. } => {
                    match status {
                        StatusCode::NotFound => {
                            return nss_entry_not_available(errnop);
                        }
                        _ => {
                            return nss_out_of_service(errnop);
                        }
                    }
                }
                _ => {
                    return nss_out_of_service(errnop);
                }
            };
        }
    };

    unsafe {
        (*pw).pw_uid = userinfo.userid as uid_t;
        (*pw).pw_gid = config.default_user_group_id as gid_t;
    }

    match fill_passwd_buf(pw, buffer, buflen, &userinfo.username, userinfo.fullname) {
        Ok(()) => NssStatus::Success as i32,
        Err(e) => {
            match e {
                BufferFillError::ZeroByteInString => nss_entry_not_available(errnop),
                _ => nss_insufficient_buffer(errnop),
            }
        }
    }
}


/// This function accepts Rust structures and copies their contents into the buffer provided to
/// store the contents of the provided C struct passwd.
///
/// This function does no allocation/reallocation. If there is not enough buffer space to store
/// everything, the function returns and relies upon the NSS caller to reallocate.
///
/// This function _does not_ expose any Rust structures to C, but instead performs bytewise
/// nonoverlapping copies into `buffer`.
///
/// Modifies `pw` and `buffer`.
///
/// This arbitrarily sets the password field of the `pw` struct to `.` because OpenSSH interprets
/// `*` as indicating a locked account.
fn fill_passwd_buf(pw: *mut passwd,
                   buffer: *mut c_char,
                   buflen: size_t,
                   username: &str,
                   fullname: String)
                   -> BufferFillResult<()> {
    if pw.is_null() || buffer.is_null() || buflen == 0 {
        return Err(BufferFillError::NullPointerError);
    }
    let c_name = CString::new(username)?.into_bytes_with_nul();
    let c_passwd = CString::new(".")?.into_bytes_with_nul();
    let c_gecos = CString::new(fullname)?.into_bytes_with_nul();
    let c_dir = CString::new(format!("/home/{}", username))?
        .into_bytes_with_nul();
    let c_shell = CString::new("/bin/bash")?.into_bytes_with_nul();

    if buflen < c_name.len() + c_passwd.len() + c_gecos.len() + c_dir.len() + c_shell.len() {
        return Err(BufferFillError::InsufficientBuffer);
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

/// One of the functions used ran temporarily out of resources or a service is currently not
/// available.
fn nss_out_of_service(errnop: *mut i32) -> i32 {
    unsafe { *errnop = EAGAIN };
    NssStatus::TryAgain as i32
}

/// The provided buffer is not large enough. The function should be called again with a larger
/// buffer.
fn nss_insufficient_buffer(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ERANGE };
    NssStatus::TryAgain as i32
}

/// A necessary input file cannot be found.
fn nss_input_file_err(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ENOENT };
    NssStatus::Unavailable as i32
}

/// The requested entry is not available.
fn nss_entry_not_available(errnop: *mut i32) -> i32 {
    unsafe { *errnop = ENOENT };
    NssStatus::NotFound as i32
}

/// There are no entries. Use this to avoid returning errors for inactive services which may be
/// enabled at a later time. This is not the same as the service being temporarily unavailable.
fn nss_no_entries_available(_: *mut i32) -> i32 {
    NssStatus::NotFound as i32
}
