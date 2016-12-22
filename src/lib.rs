extern crate rustc_serialize;
extern crate openssl;
extern crate byteorder;

use std::path::Path;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::result;
use std::convert;

use rustc_serialize::json;
use openssl::error::ErrorStack;

mod opdata01;
pub use opdata01::OpdataError;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    Json(json::ParserError),
    OpdataError(OpdataError),
    OpenSSL(ErrorStack),
}

impl convert::From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl convert::From<json::ParserError> for Error {
    fn from(e: json::ParserError) -> Self {
        Error::Json(e)
    }
}

impl convert::From<OpdataError> for Error {
    fn from(e: OpdataError) -> Self {
        Error::OpdataError(e)
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Error::OpenSSL(e)
    }
}

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct Profile {
    pub last_updated_by: String,
    pub updated_at: i64,
    pub profile_name: String,
    pub salt: String,
    pub password_hint: Option<String>,
    pub master_key: String,
    pub iterations: i64,
    pub uuid: String,
    pub overview_key: String,
    pub created_at: i64,
}

pub fn read_profile(p: &Path) -> Result<Profile> {
    let mut f = try!(File::open(p));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("var profile=").trim_right_matches(';');
    let json_struct = try!(json::Json::from_str(json_str));

    Ok(Profile {
        last_updated_by: json_struct["lastUpdatedBy"].as_string().expect("lastUpdatedBy").into(),
        updated_at: json_struct["updatedAt"].as_i64().expect("updatedAt"),
        profile_name: json_struct["profileName"].as_string().expect("profileName").into(),
        salt: json_struct["salt"].as_string().expect("salt").into(),
        password_hint: None,//json_struct["passwordHint"].as_string().map(|s| s.into()),
        master_key: json_struct["masterKey"].as_string().expect("masterKey").into(),
        iterations: json_struct["iterations"].as_i64().expect("iterations"),
        uuid: json_struct["uuid"].as_string().expect("uuid").into(),
        overview_key: json_struct["overviewKey"].as_string().expect("overviewKey").into(),
        created_at: json_struct["createdAt"].as_i64().expect("createdAt"),
    })
}

#[cfg(test)]
mod tests {
    use openssl::pkcs5::pbkdf2_hmac;
    use openssl::hash::MessageDigest;

    #[test]
    fn read_profile() {
        use std::path::Path;
        use rustc_serialize::base64::{FromBase64};
        use super::opdata01;

        let profile = super::read_profile(Path::new("onepassword_data/default/profile.js")).unwrap();

        let mut pw_derived = [0u8; 64];
        pbkdf2_hmac("freddy".as_bytes(), profile.salt.from_base64().unwrap().as_slice(), 50000, MessageDigest::sha512(), &mut pw_derived).unwrap();

        opdata01::decrypt(profile.master_key.from_base64().unwrap().as_slice(), &pw_derived[..32], &pw_derived[32..]).unwrap();
    }
}
