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
use std::io::ErrorKind;
use std::collections::HashMap;
use std::str::FromStr;
use std::result;

use super::crypto::{verify_data, decrypt_data, hmac};
use super::opdata01;
use super::{Result, Error, MasterKey, OverviewKey, ItemKey, HmacKey, Uuid, Attachment};

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
    fave: Option<i64>,
    folder: Option<String>,
    hmac: String,
    k: String,
    o: String,
    trashed: Option<bool>,
    tx: i64,
    updated: i64,
    uuid: String,
}

macro_rules! update {
    ($s: expr, $name:expr, $field:expr) => {
        try!($s.update($name.as_bytes()));
        try!($s.update($field.to_string().as_bytes()));
    };
    (option, $s: expr, $name:expr, $field:expr) => {
        if let Some(ref x) = $field {
            try!($s.update($name.as_bytes()));
            try!($s.update(x.to_string().as_bytes()));
        }
    };
}

impl ItemData {
    /// Create from the json structure, verifying the integrity of the data given the master hmac key
    fn verify(&self, key: &HmacKey) -> Result<bool> {
        let actual_hmac = try!(hmac(key, |signer| {
            // This is far from optimal, but we need idents and strings here so any
            // option is bound to lead to some duplication.
            update!(signer, "category", self.category);
            update!(signer, "created", self.created);
            update!(signer, "d", self.d);
            update!(option, signer, "fave", self.fave);
            update!(option, signer, "folder", self.folder);
            update!(signer, "k", self.k);
            update!(signer, "o", self.o);
            // Although this is boolean in the JSON, the HMAC is calculated with
            // this as an integer.
            update!(option, signer, "trashed", self.trashed.map(|x| x as i32));
            update!(signer, "tx", self.tx);
            update!(signer, "updated", self.updated);
            update!(signer, "uuid", self.uuid);
            Ok(())
        }));

        let expected_hmac = try!(self.hmac.from_base64());

        Ok(expected_hmac == actual_hmac)
    }
}

/// An encrypted piece of information.
#[derive(Debug)]
pub struct Item {
    pub category: Category,
    pub created: i64,
    pub d: Vec<u8>,
    pub folder: Option<Uuid>,
    pub hmac: Vec<u8>,
    pub k: Vec<u8>,
    pub o: Vec<u8>,
    pub tx: i64,
    pub updated: i64,
    pub uuid: Uuid,
    pub fave: Option<i64>,
    pub attachments: HashMap<Uuid, Attachment>,
}

impl Item {
    fn from_item_data(d: ItemData, atts: &mut HashMap<Uuid, Attachment>, key: &HmacKey) -> Result<Item> {
        if !try!(d.verify(key)) {
            return Err(Error::ItemError);
        }

        let uuid = try!(Uuid::parse_str(&d.uuid));
        let folder_uuid = if let Some(id) = d.folder {
            Some(try!(Uuid::parse_str(&id)))
        } else {
            None
        };

        let wanted: Vec<Uuid> = atts.iter().filter(|&(_, ref a)| a.item == uuid).map(|(k, _)| *k).collect();
        let mut attachments = HashMap::new();
        for k in wanted {
            attachments.insert(k, atts.remove(&k).unwrap());
        }

        Ok(Item {
            category: try!(Category::from_str(&d.category)),
            created: d.created,
            d: try!(d.d.from_base64()),
            folder: folder_uuid,
            hmac: try!(d.hmac.from_base64()),
            k: try!(d.k.from_base64()),
            o: try!(d.o.from_base64()),
            tx: d.tx,
            updated: d.updated,
            uuid: uuid,
            fave: d.fave,
            attachments: attachments,
        })
    }

    /// decrypt this item's details given the master encryption and hmac keys.
    pub fn decrypt_detail(&self, key: &MasterKey) -> Result<Vec<u8>> {
        let keys = try!(self.item_key(key));
        match opdata01::decrypt(&self.d[..], keys.encryption(), keys.verification()) {
            Ok(x) => Ok(x),
            Err(e) => Err(From::from(e)),
        }
    }

    /// decrypt the item's overview given the overview encryption and hmac keys.
    pub fn decrypt_overview(&self, key: &OverviewKey) -> Result<Vec<u8>> {
        match opdata01::decrypt(&self.o[..], key.encryption(), key.verification()) {
            Ok(x) => Ok(x),
            Err(e) => Err(From::from(e)),
        }
    }

    pub fn item_key(&self, key: &MasterKey) -> Result<ItemKey> {
        if !try!(verify_data(&self.k[..], key.verification())) {
            return Err(Error::ItemError);
        }

        let iv = &self.k[..16];
        let keys = try!(decrypt_data(&self.k[16..], key.encryption(), iv));

        Ok(keys.into())
    }
}

static BANDS: &'static [u8; 16] = b"0123456789ABCDEF";

// Load the items given the containing path
pub fn read_items(p: &Path, atts: &mut HashMap<Uuid, Attachment>, key: &HmacKey) -> Result<HashMap<Uuid, Item>> {
    let mut map = HashMap::new();
    for x in BANDS.iter() {
        let name = format!("band_{}.js", *x as char);
        let path = p.join(name);
        let items = try!(read_band(&path, atts, key));
        map.extend(items);
    }

    Ok(map)
}

fn read_band(p: &Path, atts: &mut HashMap<Uuid, Attachment>, key: &HmacKey) -> Result<HashMap<Uuid, Item>> {
    let mut f = match File::open(p) {
        Err(ref e) if e.kind() == ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(From::from(e)),
        Ok(x) => x,
    };
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    let json_str = s.trim_left_matches("ld(").trim_right_matches(");");

    let mut items: HashMap<Uuid, ItemData> = try!(json::decode(json_str));
    let mut map = HashMap::new();
    for (k, v) in items.drain() {
        map.insert(k, try!(Item::from_item_data(v, atts, key)));
    }

    Ok(map)
}
