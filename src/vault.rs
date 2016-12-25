use std::path::{Path, PathBuf};
use std::collections::HashMap;

use super::Result;
use super::{Profile, Folder, Item, HmacKey};
use super::{folder, profile, item};

/// An OPVault, which can be encrypted (sealed) or decrypted once the passphrase
/// is provided.

/// This represents a vault under a particular profile.
#[derive(Debug)]
pub struct Vault {
    base: PathBuf,
    /// The profile information, including the password hint and master and
    /// overview keys.
    pub profile: Profile,
    /// The folders in this vault, keyed by UUID
    pub folders: HashMap<String, Folder>,
    /// The items in this vault.
    pub items: Option<HashMap<String, Item>>,
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
