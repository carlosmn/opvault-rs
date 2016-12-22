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
pub struct Folder {
    pub created: i64,
    pub overview: String,
    pub tx: i64,
    pub updated: i64,
    pub uuid: String,
    pub smart: Option<bool>,
}

pub fn read_folders(p: &Path, key: &DerivedKey) -> Result<HashMap<String,Folder>> {
    let mut f = try!(File::open(p));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    // the file looks like it's meant to be eval'ed by a JS engine, which sounds
    // like a particularly bad idea, let's remove the non-json bits.
    let json_str = s.trim_left_matches("loadFolders(").trim_right_matches(");");
    println!("json_str {}", json_str);

    let mut folders: HashMap<String,Folder> = try!(json::decode(json_str));

    for (_, folder) in folders.iter_mut() {
        let overview_data = try!(folder.overview.from_base64());
        folder.overview = try!(String::from_utf8(try!(opdata01::decrypt(overview_data.as_slice(), &key.encrypt, &key.hmac))));
    }

    Ok(folders)
}
