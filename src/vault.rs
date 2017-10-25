// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::rc::Rc;
use super::Result;
use super::{Profile, Folder, Item, Uuid, MasterKey, OverviewKey};
use super::{folder, profile, item, attachment, crypto, opdata01};
use super::item::{ItemData, ItemIterator};
use super::attachment::AttachmentData;

/// A locked vault has just been created and has not loaded any items or
/// attachments. It contains just enough information to try to unseal it.
#[derive(Debug)]
pub struct LockedVault {
    base: PathBuf,
    /// The profile information, including the password hint and master and
    /// overview keys.
    pub profile: Profile,
}

impl LockedVault {
    /// Read the vault's profile data into memory. This lets the application
    /// provide a password hint to the user.
    pub fn open(path: &Path) -> Result<LockedVault> {
        let base = path.join("default");
        let profile = try!(profile::read_profile(&base.join("profile.js")));

        Ok(LockedVault {
            base: base,
            profile: profile,
        })
    }

    /// Unlock this vault with the user's master password
    pub fn unlock(self, password: &[u8]) -> Result<UnlockedVault> {
        let (master, overview) = try!(self.decrypt_keys(password));
        UnlockedVault::new(self.base, self.profile, Rc::new(master), Rc::new(overview))
    }

    /// Decrypt and derive the master and overview keys given the user's master
    /// password. The master keys can be used to retrieve item details and the
    /// overview keys decrypt item and folder overview data.
    fn decrypt_keys(&self, password: &[u8]) -> Result<(MasterKey, OverviewKey)> {
        let key = try!(crypto::pbkdf2(password, &self.profile.salt[..], self.profile.iterations as usize));
        let decrypt_key = &key[..32];
        let hmac_key = &key[32..];

        let master_key = try!(derive_key(&self.profile.master_key[..], decrypt_key, hmac_key));
        let overview_key = try!(derive_key(&self.profile.overview_key[..], decrypt_key, hmac_key));

        Ok((master_key.into(), overview_key.into()))
    }
}

/// Derive a key from its opdata01-encoded source
fn derive_key(data: &[u8], decrypt_key: &[u8], hmac_key: &[u8]) -> Result<Vec<u8>> {
    let key_plain = try!(opdata01::decrypt(data, decrypt_key, hmac_key));
    let hashed = try!(crypto::hash_sha512(key_plain.as_slice()));

    Ok(hashed)
}

/// An unlocked vault has loaded the encrypted items and attachments and
/// contains the keys necessary to decrypt the contents.
#[derive(Debug)]
pub struct UnlockedVault {
    base: PathBuf,
    /// The profile information, including the password hint and master and
    /// overview keys.
    pub profile: Profile,
    /// The folders in this vault, keyed by their UUID
    pub folders: HashMap<Uuid, Folder>,
    /// The items in this vault.
    items: HashMap<Uuid, ItemData>,
    attachments: HashMap<Uuid, (AttachmentData, PathBuf)>,

    /// Master key
    master: Rc<MasterKey>,
    /// Overview key
    overview: Rc<OverviewKey>,
}

impl UnlockedVault {
    /// Read the encrypted data in a vault. We assume the profile is "default"
    /// which is the only one currently in use. This is primarily for use by
    /// `LockedVault`'s `unlock` method.
    fn new(base: PathBuf, profile: Profile, master: Rc<MasterKey>, overview: Rc<OverviewKey>) -> Result<UnlockedVault> {
        let folders = try!(folder::read_folders(&base.join("folders.js"), overview.clone()));
        let attachments = try!(attachment::read_attachments(&base));
        let items = try!(item::read_items(&base, overview.clone()));

        Ok(UnlockedVault {
            base: base,
            profile: profile,
            folders: folders,
            items: items,
            attachments: attachments,
            master: master,
            overview: overview,
        })
    }

    pub fn get_item(&self, id: &Uuid) -> Option<Item> {
        let data = self.items.get(id);
        if let Some(item_data) = data {
            item::item_from_data(item_data, &self.attachments, self.master.clone(), self.overview.clone()).ok()
        } else {
            None
        }
    }

    pub fn get_items(&self) -> ItemIterator {
        ItemIterator {
            inner: self.items.values(),
            master: self.master.clone(),
            overview: self.overview.clone(),
            attachments: &self.attachments,
        }
    }
}
