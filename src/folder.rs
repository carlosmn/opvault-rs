// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;
use std::rc::Rc;

use serde_json;
use base64;
use super::opdata01;
use super::{Result, OverviewKey, Uuid};

#[derive(Debug, Deserialize)]
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
    pub tx: i64,
    pub updated: i64,
    pub uuid: Uuid,
    pub smart: Option<bool>,
    overview: Vec<u8>,
    overview_key: Rc<OverviewKey>
}

impl Folder {
    fn from_folder_data(d: FolderData, overview_key: Rc<OverviewKey>) -> Result<Folder> {
        let overview = try!(base64::decode(&d.overview));
        Ok(Folder {
            created: d.created,
            overview: overview,
            tx: d.tx,
            updated: d.updated,
            uuid: d.uuid,
            smart: d.smart,
            overview_key: overview_key,
        })
    }

    /// Decrypt the folder's overview data
    pub fn overview(&self) -> Result<Vec<u8>> {
        let key = self.overview_key.clone();
        match opdata01::decrypt(&self.overview[..], key.encryption(), key.verification()) {
            Ok(x) => Ok(x),
            Err(e) => Err(From::from(e)),
        }
    }
}

/// Read the encrypted folder data
pub fn read_folders(p: &Path, overview_key: Rc<OverviewKey>) -> Result<HashMap<Uuid, Folder>> {
    let mut f = try!(File::open(p));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("loadFolders(").trim_right_matches(");");
    let mut folder_datas: HashMap<Uuid, FolderData> = try!(serde_json::from_str(json_str));
    let mut folders = HashMap::new();

    for (k, v) in folder_datas.drain() {
        folders.insert(k, try!(Folder::from_folder_data(v, overview_key.clone())));
    }

    Ok(folders)
}
