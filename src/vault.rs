// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::{Path, PathBuf};
use std::collections::HashMap;

use super::Result;
use super::{Profile, Folder, Item, HmacKey, Uuid};
use super::{folder, profile, item};

/// This represents a vault for a particular profile.
#[derive(Debug)]
pub struct Vault {
    base: PathBuf,
    /// The profile information, including the password hint and master and
    /// overview keys.
    pub profile: Profile,
    /// The folders in this vault, keyed by their UUID
    pub folders: HashMap<Uuid, Folder>,
    /// The items in this vault.
    pub items: Option<HashMap<Uuid, Item>>,
}

impl Vault {
    /// Read the encrypted data in a vault. We assume the profile is "default"
    /// which is the only one currently in use.
    pub fn new(p: &Path) -> Result<Vault> {
        let base = p.join("default");
        let folders = try!(folder::read_folders(&base.join("folders.js")));
        let profile = try!(profile::read_profile(&base.join("profile.js")));

        Ok(Vault {
            base: base,
            profile: profile,
            folders: folders,
            items: None,
        })
    }

    /// Read the items vault into memory. The master HMAC key is used to check
    /// the integrity of the item data.
    pub fn read_items(&mut self, key: &HmacKey) -> Result<()> {
        let items = try!(item::read_items(&self.base, key));
        self.items = Some(items);
        Ok(())
    }
}
