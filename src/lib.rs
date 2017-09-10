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

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate openssl;
extern crate base64;
extern crate byteorder;
extern crate uuid;

use std::io;
use std::result;
use std::convert;
use std::string::FromUtf8Error;

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
pub use item::{Item, Category};
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
    JsonError(serde_json::Error),
    Base64Error(base64::DecodeError),
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

impl convert::From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e)
    }
}

impl convert::From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64Error(e)
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
        assert_eq!(3, unlocked.folders.len());

        for (_uuid, folder) in &unlocked.folders {
            folder.overview().expect("folder overview");
        }

        let item_uuid = Uuid::parse_str("F2DB5DA3FCA64372A751E0E85C67A538").expect("uuid");
        let item = unlocked.get_item(&item_uuid).expect("item lookiup");
        let _overview = item.overview().expect("item overview");
        let _decrypted = item.detail().expect("item detail");
        assert_eq!(2, item.get_attachments().expect("attachments").count());
        let att_uuid = Uuid::parse_str("23F6167DC1FB457A8DE7033ACDCD06DB").expect("uuid");
        let _att = item.get_attachment(&att_uuid).expect("attachment");
        let _overview = _att.decrypt_overview().expect("decrypt overview");
        let _icon = _att.decrypt_icon().expect("decrypt icon");
        let _content = _att.decrypt_content().expect("decrypt content");

        for _item in unlocked.get_items() {
            for _att in _item.get_attachments().expect("attachments") {
                let _overview = _att.decrypt_overview().expect("decrypt overview");
                let _icon = _att.decrypt_icon().expect("decrypt icon");
                let _content = _att.decrypt_content().expect("decrypt content");
            }
        }
    }
}
