// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use rustc_serialize::json;
use rustc_serialize::base64::FromBase64;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;

use super::opdata01;
use super::{Result, DerivedKey, Uuid};

#[derive(Debug, RustcDecodable)]
pub struct FolderData {
    pub created: i64,
    pub overview: String,
    pub tx: i64,
    pub updated: i64,
    pub uuid: Uuid,
    pub smart: Option<bool>,
}

/// A "folder" or named group of items.
#[derive(Debug)]
pub struct Folder {
    pub created: i64,
    pub overview: Vec<u8>,
    pub tx: i64,
    pub updated: i64,
    pub uuid: Uuid,
    pub smart: Option<bool>,
}

impl Folder {
    fn from_folder_data(d: FolderData) -> Result<Folder> {
        let overview = try!(d.overview.from_base64());
        Ok(Folder {
            created: d.created,
            overview: overview,
            tx: d.tx,
            updated: d.updated,
            uuid: d.uuid,
            smart: d.smart,
        })
    }

    /// Decrypt the folder's overview data given the overview keys
    pub fn decrypt_overview(&self, key: &DerivedKey) -> Result<Vec<u8>> {
        match opdata01::decrypt(&self.overview[..], &key.encrypt, &key.hmac) {
            Ok(x) => Ok(x),
            Err(e) => Err(From::from(e)),
        }
    }
}

/// Read the encrypted folder data
pub fn read_folders(p: &Path) -> Result<HashMap<Uuid, Folder>> {
    let mut f = try!(File::open(p));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("loadFolders(").trim_right_matches(");");
    let mut folder_datas: HashMap<Uuid, FolderData> = try!(json::decode(json_str));
    let mut folders = HashMap::new();

    for (k, v) in folder_datas.drain() {
        folders.insert(k, try!(Folder::from_folder_data(v)));
    }

    Ok(folders)
}
