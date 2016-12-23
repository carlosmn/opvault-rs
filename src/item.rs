use rustc_serialize::json;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::collections::HashMap;

use super::Result;

#[derive(Debug, RustcDecodable)]
pub struct Item {
    category: String,
    created: i64,
    d: String,
    folder: Option<String>,
    hmac: String,
    k: String,
    o: String,
    tx: i64,
    updated: i64,
    uuid: String,
    fave: Option<i64>,
}

static BANDS: &'static [u8; 16] = b"0123456789ABCDEF";

// Load the items given the containing path
pub fn read_items(p: &Path) -> Result<HashMap<String, Item>> {
    let mut map = HashMap::new();
    for x in BANDS.iter() {
        let name = format!("band_{}.js", *x as char);
        let path = p.join(name);
        let items = try!(read_band(&path));
        map.extend(items);
    }

    Ok(map)
}

fn read_band(p: &Path) -> Result<HashMap<String, Item>> {
    let mut f = match File::open(p) {
        Err(ref e) if e.kind() == ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(From::from(e)),
        Ok(x) => x,
    };
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    let json_str = s.trim_left_matches("ld(").trim_right_matches(");");

    let items: HashMap<String, Item> = try!(json::decode(json_str));

    Ok(items)
}
