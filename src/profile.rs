// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use rustc_serialize::base64::FromBase64;
use rustc_serialize::json;

use super::{Result, DerivedKey};
use super::{crypto, opdata01};

/// The profile data from the file, the names match the keys in the file.
#[derive(Debug, RustcDecodable)]
#[allow(non_snake_case)]
struct ProfileData {
    pub lastUpdatedBy: String,
    pub updatedAt: i64,
    pub profileName: String,
    pub salt: String,
    pub passwordHint: Option<String>,
    pub masterKey: String,
    pub iterations: u64,
    pub uuid: String,
    pub overviewKey: String,
    pub createdAt: i64,
}

/// The information for a particular profile. This includes the encrypted master
/// and overview keys, which are used to decrypt the details and superficial
/// information respectively.
#[derive(Debug)]
pub struct Profile {
    pub last_updated_by: String,
    pub updated_at: i64,
    pub profile_name: String,
    pub salt: Vec<u8>,
    pub password_hint: Option<String>,
    pub master_key: Vec<u8>,
    pub iterations: u64,
    pub uuid: String,
    pub overview_key: Vec<u8>,
    pub created_at: i64
}

impl Profile {
    fn from_profile_data(d: ProfileData) -> Result<Profile> {
        let salt = try!(d.salt.from_base64());
        let master_key = try!(d.masterKey.from_base64());
        let overview_key = try!(d.overviewKey.from_base64());

        Ok(Profile {
            last_updated_by: d.lastUpdatedBy,
            updated_at: d.updatedAt,
            profile_name: d.profileName,
            salt: salt,
            password_hint: d.passwordHint,
            master_key: master_key,
            iterations: d.iterations,
            uuid: d.uuid,
            overview_key: overview_key,
            created_at: d.createdAt,
        })
    }

    /// Decrypt and derive the master and overview keys given the user's master
    /// password. The master keys can be used to retrieve item details and the
    /// overview keys decrypt item and folder overview data.
    pub fn decrypt_keys(&self, password: &[u8]) -> Result<(DerivedKey, DerivedKey)> {
        let key = try!(crypto::pbkdf2(password, &self.salt[..], self.iterations as usize));
        let decrypt_key = &key[..32];
        let hmac_key = &key[32..];

        let master_key = try!(derive_key(&self.master_key[..], decrypt_key, hmac_key));
        let overview_key = try!(derive_key(&self.overview_key[..], decrypt_key, hmac_key));

        Ok((master_key, overview_key))
    }
}

/// Derive a key from its opdata01-encoded source
fn derive_key(data: &[u8], decrypt_key: &[u8], hmac_key: &[u8]) -> Result<DerivedKey> {
    let key_plain = try!(opdata01::decrypt(data, decrypt_key, hmac_key));
    let hashed = try!(crypto::hash_sha512(key_plain.as_slice()));

    let mut encrypt = [0u8; 32];
    let mut hmac = [0u8; 32];

    encrypt.clone_from_slice(&hashed[..32]);
    hmac.clone_from_slice(&hashed[32..]);

    Ok(DerivedKey {
        encrypt: encrypt,
        hmac: hmac,
    })
}


// Read in the profile. If the user's master password is given, we also decrypt the master and overview keys
pub fn read_profile(p: &Path) -> Result<Profile> {
    let mut f = try!(File::open(p));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("var profile=").trim_right_matches(';');
    let profile_data: ProfileData = try!(json::decode(json_str));

    Profile::from_profile_data(profile_data)
}