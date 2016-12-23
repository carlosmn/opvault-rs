use rustc_serialize::json;
use rustc_serialize::base64::FromBase64;
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::collections::HashMap;
use std::str::FromStr;
use std::result;

use super::opdata01::{verify_data, decrypt_data};
use super::opdata01;
use super::{Result, Error, DerivedKey};

/// These are the kinds of items that 1password knows about
#[derive(Debug, Copy, Clone)]
pub enum Category {
    Login,
    CreditCard,
    SecureNote,
    Identity,
    Password,
    Tombstone,
    SoftwareLicense,
    BankAccount,
    Database,
    DriverLicense,
    OutdoorLicense,
    Membership,
    Passport,
    Rewards,
    SSN,
    Router,
    Server,
    Email,
}

impl FromStr for Category {
    type Err = Error;
    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        match s {
            "001" => Ok(Category::Login),
            "002" => Ok(Category::CreditCard),
            "003" => Ok(Category::SecureNote),
            "004" => Ok(Category::Identity),
            "005" => Ok(Category::Password),
            "099" => Ok(Category::Tombstone),
            "100" => Ok(Category::SoftwareLicense),
            "101" => Ok(Category::BankAccount),
            "102" => Ok(Category::Database),
            "103" => Ok(Category::DriverLicense),
            "104" => Ok(Category::OutdoorLicense),
            "105" => Ok(Category::Membership),
            "106" => Ok(Category::Passport),
            "107" => Ok(Category::Rewards),
            "108" => Ok(Category::SSN),
            "109" => Ok(Category::Router),
            "110" => Ok(Category::Server),
            "111" => Ok(Category::Email),
            _ => Err(Error::ItemError),
        }
    }
}

#[derive(Debug, RustcDecodable)]
struct ItemData {
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

#[derive(Debug)]
pub struct Item {
    pub category: Category,
    pub created: i64,
    pub d: Vec<u8>,
    pub folder: Option<String>,
    pub hmac: Vec<u8>,
    pub k: Vec<u8>,
    pub o: Vec<u8>,
    pub tx: i64,
    pub updated: i64,
    pub uuid: String,
    pub fave: Option<i64>,
}

impl Item {
    fn from_item_data(d: ItemData) -> Result<Item> {
        Ok(Item {
            category: try!(Category::from_str(&d.category)),
            created: d.created,
            d: try!(d.d.from_base64()),
            folder: d.folder,
            hmac: try!(d.hmac.from_base64()),
            k: try!(d.k.from_base64()),
            o: try!(d.o.from_base64()),
            tx: d.tx,
            updated: d.updated,
            uuid: d.uuid,
            fave: d.fave,
        })
    }

    /// decrypt this item's details given the master encryption and hmac keys.
    pub fn decrypt_detail(&self, key: &DerivedKey) -> Result<Vec<u8>> {
        if !try!(verify_data(&self.k[..], &key.hmac)) {
            return Err(Error::ItemError);
        }

        let iv = &self.k[..16];
        let keys = try!(decrypt_data(&self.k[16..], &key.encrypt, iv));

        match opdata01::decrypt(&self.d[..], &keys[..32], &keys[32..64]) {
            Ok(x) => Ok(x),
            Err(e) => Err(From::from(e)),
        }
    }
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

    let mut items: HashMap<String, ItemData> = try!(json::decode(json_str));
    let mut map = HashMap::new();
    for (k, v) in items.drain() {
        map.insert(k, try!(Item::from_item_data(v)));
    }

    Ok(map)
}
