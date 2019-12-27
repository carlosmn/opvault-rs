// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::collections::HashMap;
use std::rc::Rc;

use serde::de;
use serde::Deserialize;
use serde_json;
use base64;
use super::opdata01;
use super::{Result, OverviewKey, Uuid};

#[derive(Debug, Deserialize)]
pub struct FolderData {
    pub created: i64,
    #[serde(deserialize_with = "base64_deser")]
    pub overview: Vec<u8>,
    pub tx: i64,
    pub updated: i64,
    pub uuid: Uuid,
    #[serde(default)]
    pub smart: bool,
}

/// A "folder" or named group of items.
#[derive(Debug)]
pub struct Folder {
    pub created: i64,
    pub tx: i64,
    pub updated: i64,
    pub uuid: Uuid,
    pub smart: bool,
    overview: Vec<u8>,
    overview_key: Rc<OverviewKey>
}

impl Folder {
    fn from_folder_data(d: FolderData, overview_key: Rc<OverviewKey>) -> Result<Folder> {
        Ok(Folder {
            created: d.created,
            overview: d.overview,
            tx: d.tx,
            updated: d.updated,
            uuid: d.uuid,
            smart: d.smart,
            overview_key,
        })
    }

    /// Decrypt the folder's overview data
    pub fn overview(&self) -> Result<Overview> {
        let key = self.overview_key.clone();
        let raw = opdata01::decrypt(&self.overview[..], key.encryption(), key.verification())?;
        match Overview::from_slice(&raw) {
            Ok(x) => Ok(x),
            Err(e) => Err(From::from(e)),
        }
    }
}

/// Read the encrypted folder data
pub fn read_folders(p: &Path, overview_key: Rc<OverviewKey>) -> Result<HashMap<Uuid, Folder>> {
    let mut f = match File::open(p) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(From::from(e)),
    };

    let mut s = String::new();
    f.read_to_string(&mut s)?;
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_start_matches("loadFolders(").trim_end_matches(");");
    let mut folder_datas: HashMap<Uuid, FolderData> = serde_json::from_str(json_str)?;
    let mut folders = HashMap::new();

    for (k, v) in folder_datas.drain() {
        folders.insert(k, Folder::from_folder_data(v, overview_key.clone())?);
    }

    Ok(folders)
}

#[derive(Debug, Deserialize)]
pub struct Overview {
    pub title: String,
    // Smart folders have a predicate, but the one from the sample set contains
    // some invalid text, and it decodes into binary anyway.
    // #[serde(rename = "predicate_b64", deserialize_with = "base64_deser")]
    // pub predicate: Vec<u8>,
}

fn base64_deser<'de, D> (d: D) -> std::result::Result<Vec<u8>, D::Error>
    where D: de::Deserializer<'de>
{
    let s = String::deserialize(d)?;
    match base64::decode(&s) {
        Ok(d) => Ok(d),
        Err(e) => Err(de::Error::custom(e.to_string())),
    }
}

impl Overview {
    pub fn from_slice(d: &[u8]) -> serde_json::Result<Overview> {
        serde_json::from_slice(d)
    }
}
