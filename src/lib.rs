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

mod opdata01;
pub use opdata01::OpdataError;

mod folder;
mod item;
mod crypto;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    Json(json::ParserError),
    JsonDecoder(json::DecoderError),
    FromBase64(FromBase64Error),
    OpdataError(OpdataError),
    Crypto(crypto::Error),
    FromUtf8Error(std::string::FromUtf8Error),
    ItemError,
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

pub type EncryptionKey = [u8; 32];
pub type HmacKey = [u8; 32];

pub struct DerivedKey {
    pub encrypt: EncryptionKey,
    pub hmac: HmacKey,
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
            let salt = try!(profile_data.salt.from_base64());
            let pw_derived = try!(crypto::pbkdf2(pw, &salt[..], profile_data.iterations as usize));
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
    let hashed = try!(crypto::hash_sha512(key_plain.as_slice()));
    //let hashed = try!(hash::hash(MessageDigest::sha512(), key_plain.as_slice()));

    let mut encrypt = [0u8; 32];
    let mut hmac = [0u8; 32];

    encrypt.clone_from_slice(&hashed[..32]);
    hmac.clone_from_slice(&hashed[32..]);

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
        let items = super::item::read_items(Path::new("onepassword_data/default"), &profile.overview_key.as_ref().expect("overview key").hmac).expect("items");
        let _decrypted = items["5ADFF73C09004C448D45565BC4750DE2"].decrypt_detail(profile.master_key.as_ref().unwrap()).unwrap();
        let _overview = items["5ADFF73C09004C448D45565BC4750DE2"].decrypt_overview(profile.overview_key.as_ref().unwrap()).expect("overview");
    }
}
