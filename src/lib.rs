extern crate rustc_serialize;
extern crate openssl;
extern crate byteorder;

use std::io;
use std::result;
use std::convert;

use rustc_serialize::base64::FromBase64Error;
use rustc_serialize::json;

mod opdata01;
pub use opdata01::OpdataError;

mod profile;
mod folder;
mod item;
mod crypto;
mod vault;

pub use profile::Profile;
pub use item::Item;
pub use folder::Folder;
pub use vault::Vault;

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

pub type EncryptionKey = [u8; 32];
pub type HmacKey = [u8; 32];

#[derive(Debug)]
pub struct DerivedKey {
    pub encrypt: EncryptionKey,
    pub hmac: HmacKey,
}

#[cfg(test)]
mod tests {
    #[test]
    fn read_vault() {
        use std::path::Path;
        use super::Vault;

        let mut vault = Vault::new(Path::new("onepassword_data")).expect("vault");
        assert_eq!(3, vault.folders.len());

        let (master, overview) = vault.profile.decrypt_keys(b"freddy").expect("keys");
        vault.read_items(&overview.hmac).expect("read_items");
        assert_eq!(29, vault.items.as_ref().expect("items").len());

        let _decrypted = vault.items.as_ref().expect("items")["5ADFF73C09004C448D45565BC4750DE2"].decrypt_detail(&master).expect("item");
        let _overview = vault.items.as_ref().expect("items")["5ADFF73C09004C448D45565BC4750DE2"].decrypt_overview(&overview).expect("item");
    }
}
