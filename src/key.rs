// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::ops::Deref;

pub type EncryptionKey = [u8];
pub type HmacKey = [u8];

/// This contains a pair of keys used for encryption and verification of the
/// different aspects of the format.
#[derive(Debug)]
pub struct Key {
    v: Vec<u8>,
}

impl Key {
    /// Retrieve a reference to the key used for encryption.
    #[inline]
    pub fn encryption(&self) -> &EncryptionKey {
        &self.v[..32]
    }

    /// Retrieve a reference to the key used for verification (HMAC)
    #[inline]
    pub fn verification(&self) -> &HmacKey {
        &self.v[32..64]
    }
}

impl From<Vec<u8>> for Key {
    fn from(v: Vec<u8>) -> Self {
        Key {
            v,
        }
    }
}

/// Alias we use to indicate we expect the master key
#[derive(Debug)]
pub struct MasterKey {
    key: Key
}

impl Deref for MasterKey {
    type Target = Key;

    fn deref(&self) -> &Key {
        &self.key
    }
}

impl From<Vec<u8>> for MasterKey {
    fn from(v: Vec<u8>) -> Self {
        Self {
            key: Key {
                v,
            }
        }
    }
}

/// Alias we use to indicate we expect the overview key
#[derive(Debug)]
pub struct OverviewKey {
    key: Key
}

impl Deref for OverviewKey {
    type Target = Key;

    fn deref(&self) -> &Key {
        &self.key
    }
}

impl From<Vec<u8>> for OverviewKey {
    fn from(v: Vec<u8>) -> Self {
        Self {
            key: Key {
                v,
            }
        }
    }
}

/// Alias we use to indicate we expect an item's key
#[derive(Debug)]
pub struct ItemKey {
    key: Key
}

impl Deref for ItemKey {
    type Target = Key;

    fn deref(&self) -> &Key {
        &self.key
    }
}

impl From<Vec<u8>> for ItemKey {
    fn from(v: Vec<u8>) -> Self {
        Self {
            key: Key {
                v,
            }
        }
    }
}
