use rustc_serialize::json;
use rustc_serialize::base64::FromBase64;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::collections::HashMap;

use super::opdata01;
use super::Result;
use super::DerivedKey;

#[derive(Debug, RustcDecodable)]
pub struct FolderData {
    pub created: i64,
    pub overview: String,
    pub tx: i64,
    pub updated: i64,
    pub uuid: String,
    pub smart: Option<bool>,
}

#[derive(Debug)]
pub struct Folder {
    pub created: i64,
    pub overview: Vec<u8>,
    pub tx: i64,
    pub updated: i64,
    pub uuid: String,
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
pub fn read_folders(p: &Path) -> Result<HashMap<String, Folder>> {
    let mut f = try!(File::open(p));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("loadFolders(").trim_right_matches(");");
    let mut folder_datas: HashMap<String, FolderData> = try!(json::decode(json_str));
    let mut folders = HashMap::new();

    for (k, v) in folder_datas.drain() {
        folders.insert(k, try!(Folder::from_folder_data(v)));
    }

    Ok(folders)
}
