extern crate rustc_serialize;
extern crate openssl;
extern crate byteorder;

use std::path::Path;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::result;
use std::convert;

use rustc_serialize::base64::{FromBase64, FromBase64Error};
use rustc_serialize::json;

use openssl::error::ErrorStack;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::hash::MessageDigest;
use openssl::hash;

mod opdata01;
pub use opdata01::OpdataError;

mod folder;
mod item;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    Json(json::ParserError),
    JsonDecoder(json::DecoderError),
    FromBase64(FromBase64Error),
    OpdataError(OpdataError),
    OpenSSL(ErrorStack),
    FromUtf8Error(std::string::FromUtf8Error)
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

impl convert::From<json::DecoderError> for Error {
    fn from(e: json::DecoderError) -> Self {
        Error::JsonDecoder(e)
    }
}

impl convert::From<FromBase64Error> for Error {
    fn from(e: FromBase64Error) -> Self {
        Error::FromBase64(e)
    }
}

impl convert::From<OpdataError> for Error {
    fn from(e: OpdataError) -> Self {
        Error::OpdataError(e)
    }
}

impl convert::From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::FromUtf8Error(e)
    }
}

impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Error::OpenSSL(e)
    }
}

pub type Result<T> = result::Result<T, Error>;

/// The profile data from the file, the names match the keys in the file.
#[derive(Debug, RustcDecodable)]
#[allow(non_snake_case)]
pub struct ProfileData {
    pub lastUpdatedBy: String,
    pub updatedAt: i64,
    pub profileName: String,
    pub salt: String,
    pub passwordHint: Option<String>,
    pub masterKey: String,
    pub iterations: i64,
    pub uuid: String,
    pub overviewKey: String,
    pub createdAt: i64,
}

/// The profile data including derived and decrypted keys.
pub struct Profile {
    /// This is the data in the file itself
    pub data: ProfileData,

    pub master_key: Option<DerivedKey>,
    pub overview_key: Option<DerivedKey>,
}

pub struct DerivedKey {
    pub encrypt: [u8; 32],
    pub hmac: [u8; 32],
}

// Read in the profile. If the user's master password is given, we also decrypt the master and overview keys
pub fn read_profile(p: &Path, password: Option<&[u8]>) -> Result<Profile> {
    let mut f = try!(File::open(p));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("var profile=").trim_right_matches(';');
    let profile_data: ProfileData = try!(json::decode(json_str));

    // Derive the password and hmac keys if given
    let (master_key, overview_key) =
        if let Some(pw) = password {
            let mut pw_derived = [0u8; 64];
            pbkdf2_hmac(pw, try!(profile_data.salt.from_base64()).as_slice(), profile_data.iterations as usize, MessageDigest::sha512(), &mut pw_derived).unwrap();
            let decrypt_key = &pw_derived[..32];
            let hmac_key = &pw_derived[32..];

            let master = try!(profile_data.masterKey.from_base64());
            let master_key = try!(derive_key(master.as_slice(), decrypt_key, hmac_key));

            let overview = try!(profile_data.overviewKey.from_base64());
            let overview_key = try!(derive_key(overview.as_slice(), decrypt_key, hmac_key));

            (Some(master_key), Some(overview_key))
        } else {
            (None, None)
        };

    Ok(Profile {
        data: profile_data,
        master_key: master_key,
        overview_key: overview_key,
    })
}

/// Derive a key from its opdata01-encoded source
fn derive_key(data: &[u8], decrypt_key: &[u8], hmac_key: &[u8]) -> Result<DerivedKey> {
    let key_plain = try!(opdata01::decrypt(data, decrypt_key, hmac_key));
    let hashed = try!(hash::hash(MessageDigest::sha512(), key_plain.as_slice()));

    let mut encrypt = [0u8; 32];
    let mut hmac = [0u8; 32];

    for i in 0..32 {
        encrypt[i] = hashed[i];
    }
    for i in 0..32 {
        hmac[i] = hashed[32+i];
    }

    Ok(DerivedKey {
        encrypt: encrypt,
        hmac: hmac,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn read_profile() {
        use std::path::Path;

        let profile = super::read_profile(Path::new("onepassword_data/default/profile.js"), Some("freddy".as_bytes())).unwrap();
        let _folders = super::folder::read_folders(Path::new("onepassword_data/default/folders.js"), profile.overview_key.as_ref().unwrap());
        let _items = super::item::read_items(Path::new("onepassword_data/default")).unwrap();
        println!("_items.len() {}", _items.len());
    }
}
