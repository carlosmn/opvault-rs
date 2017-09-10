// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use base64;
use serde_json;
use super::{Result};

/// The profile data from the file, the names match the keys in the file.
#[derive(Debug, Deserialize)]
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
        let salt = try!(base64::decode(&d.salt));
        let master_key = try!(base64::decode(&d.masterKey));
        let overview_key = try!(base64::decode(&d.overviewKey));

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

}

// Read in the profile. If the user's master password is given, we also decrypt the master and overview keys
pub fn read_profile(p: &Path) -> Result<Profile> {
    let mut f = try!(File::open(p));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("var profile=").trim_right_matches(';');
    let profile_data: ProfileData = try!(serde_json::from_str(json_str));

    Profile::from_profile_data(profile_data)
}
