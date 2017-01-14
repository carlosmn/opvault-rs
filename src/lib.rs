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
mod key;

pub use profile::Profile;
pub use item::Item;
pub use folder::Folder;
pub use vault::{LockedVault, UnlockedVault};
pub use attachment::{Attachment, AttachmentIterator};
pub use key::{Key, EncryptionKey, HmacKey};

/// Alias we use to indicate we expect the master key
pub type MasterKey = Key;
/// Alias we use to indicate we expect the overview key
pub type OverviewKey = Key;
/// Alias we use to indicate we expect an item's key
pub type ItemKey = Key;

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

#[cfg(test)]
mod tests {
    #[test]
    fn read_vault() {
        use std::path::Path;
        use super::{LockedVault, Uuid};

        let vault = LockedVault::open(Path::new("onepassword_data")).expect("vault");

        let unlocked = vault.unlock(b"freddy").expect("unlock");
        assert_eq!(29, unlocked.get_items().count());

        let item_uuid = Uuid::parse_str("5ADFF73C09004C448D45565BC4750DE2").expect("uuid");
        let item = unlocked.get_item(&item_uuid).expect("item lookiup");
        let _overview = item.overview().expect("item overview");
        let _decrypted = item.detail().expect("item detail");
        for _att in item.get_attachments().expect("attachments") {
            let _overview = _att.decrypt_overview().expect("decrypt overview");
            let _icon = _att.decrypt_icon().expect("decrypt icon");
            let _content = _att.decrypt_content().expect("decrypt content");
        }


        for _item in unlocked.get_items() {
            for _att in _item.get_attachments().expect("attachments") {
                let _overview = _att.decrypt_overview().expect("decrypt overview");
                let _icon = _att.decrypt_icon().expect("decrypt icon");
                let _content = _att.decrypt_content().expect("decrypt content");
            }
        }
    }
}
