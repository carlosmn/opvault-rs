// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Read and decrypt the OPVault format
//!
//! This is the format used by 1password, including for file-based
//! synchronization between computers.
//!
//! The user's password unlocks the vault by being converted into four paired
//! keys. Each pair of keys lets us verify the integrity of the data before
//! trying to decrypt it.
//!
//! The format is described at https://support.1password.com/opvault-design/

extern crate rustc_serialize;
extern crate openssl;
extern crate byteorder;
extern crate uuid;

use std::io;
use std::result;
use std::convert;
use std::string::FromUtf8Error;

use rustc_serialize::base64::FromBase64Error;
use rustc_serialize::json;

pub use uuid::Uuid;

mod opdata01;
pub use opdata01::OpdataError;

mod profile;
mod folder;
mod item;
mod crypto;
mod vault;
mod attachment;
mod opcldat;

pub use profile::Profile;
pub use item::Item;
pub use folder::Folder;
pub use vault::Vault;
pub use attachment::Attachment;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    JsonDecoder(json::DecoderError),
    FromBase64(FromBase64Error),
    FromUtf8Error(FromUtf8Error),
    OpdataError(OpdataError),
    Crypto(crypto::Error),
    ItemError,
    UuidError(uuid::ParseError),
    OpcldatError,
}

impl convert::From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
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

impl convert::From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::FromUtf8Error(e)
    }
}

impl convert::From<OpdataError> for Error {
    fn from(e: OpdataError) -> Self {
        Error::OpdataError(e)
    }
}

impl convert::From<uuid::ParseError> for Error {
    fn from(e: uuid::ParseError) -> Self {
        Error::UuidError(e)
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
        use super::{Vault, Uuid};

        let mut vault = Vault::new(Path::new("onepassword_data")).expect("vault");
        assert_eq!(3, vault.folders.len());

        let (master, overview) = vault.profile.decrypt_keys(b"freddy").expect("keys");
        vault.read_items(&overview.hmac).expect("read_items");
        assert_eq!(29, vault.items.as_ref().expect("items").len());

        let item_uuid = Uuid::parse_str("5ADFF73C09004C448D45565BC4750DE2").expect("uuid");
        let _decrypted = vault.items.as_ref().expect("items")[&item_uuid].decrypt_detail(&master).expect("item");
        let _overview = vault.items.as_ref().expect("items")[&item_uuid].decrypt_overview(&overview).expect("item");

        for (_, _item) in vault.items.expect("items") {
            let item_key = _item.item_key(&master).expect("item keys");
            for (_, _att) in _item.attachments {
                let _icon = _att.decrypt_icon(&item_key).expect("decrypt icon");
                let _content = _att.decrypt_content(&item_key).expect("decrypt content");
            }
        }
    }
}
