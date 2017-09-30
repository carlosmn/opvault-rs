// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::collections::HashMap;
use std::str::FromStr;
use std::result;
use std::rc::Rc;
use std::collections::hash_map::Values as HashMapValues;

use serde_json;
use base64;
use super::crypto::{verify_data, decrypt_data, hmac};
use super::opdata01;
use super::{Result, Error, MasterKey, OverviewKey, ItemKey, HmacKey, Uuid, AttachmentIterator};
use super::attachment::{AttachmentData, Attachment};
use super::attachment;
use super::detail::{self, Detail};
use super::overview::Overview;

/// These are the kinds of items that 1password knows about
#[derive(Debug, Copy, Clone, PartialEq)]
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

#[derive(Debug, Deserialize)]
pub struct ItemData {
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

        let expected_hmac = try!(base64::decode(&self.hmac));

        Ok(expected_hmac == actual_hmac)
    }
}

/// An encrypted piece of information.
#[derive(Debug)]
pub struct Item<'a> {
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
    pub attachments: Vec<Uuid>,

    atts: &'a HashMap<Uuid, (AttachmentData, PathBuf)>,
    master: Rc<MasterKey>,
    overview: Rc<OverviewKey>,
}

impl<'a> Item<'a> {
    fn from_item_data(d: &ItemData, atts: &'a HashMap<Uuid, (AttachmentData, PathBuf)>, master: Rc<MasterKey>, overview: Rc<OverviewKey>) -> Result<Item<'a>> {
        let uuid = try!(Uuid::parse_str(&d.uuid));
        let folder_uuid = if let Some(ref id) = d.folder {
            Some(try!(Uuid::parse_str(id)))
        } else {
            None
        };

        let attachments: Vec<Uuid> = atts.iter()
            .filter(|&(_, &(ref a, _))| a.itemUUID == uuid)
            .map(|(k, _)| *k)
            .collect();

        Ok(Item {
            category: try!(Category::from_str(&d.category)),
            created: d.created,
            d: try!(base64::decode(&d.d)),
            folder: folder_uuid,
            hmac: try!(base64::decode(&d.hmac)),
            k: try!(base64::decode(&d.k)),
            o: try!(base64::decode(&d.o)),
            tx: d.tx,
            updated: d.updated,
            uuid: uuid,
            fave: d.fave,
            attachments: attachments,
            atts: atts,
            master: master,
            overview: overview,
        })
    }

    /// Decrypt this item's details
    pub fn detail(&self) -> Result<Detail> {
        let keys = try!(self.item_key());
        let raw = try!(opdata01::decrypt(&self.d[..], keys.encryption(), keys.verification()));
        let res = if self.category == Category::Login {
            Detail::Login(try!(detail::Login::from_slice(&raw)))
        } else {
            Detail::Generic(try!(detail::Generic::from_slice(&raw)))
        };

        Ok(res)
    }

    /// Decrypt the item's overview
    pub fn overview(&self) -> Result<Overview> {
        let raw = opdata01::decrypt(&self.o[..], self.overview.encryption(), self.overview.verification())?;
        let res = try!(Overview::from_slice(&raw));

        Ok(res)
    }

    fn item_key(&self) -> Result<ItemKey> {
        if !try!(verify_data(&self.k[..], self.master.verification())) {
            return Err(Error::ItemError);
        }

        let iv = &self.k[..16];
        let keys = try!(decrypt_data(&self.k[16..], self.master.encryption(), iv));

        Ok(keys.into())
    }

    pub fn get_attachment(&self, id: &Uuid) -> Option<Attachment> {
        if let Ok(key) = self.item_key() {
            if let Some(&(ref data, ref p)) = self.atts.get(id) {
                return attachment::from_data(data, p.clone(), Rc::new(key), self.overview.clone()).ok()
            }
        }

        None
    }

    pub fn get_attachments(&'a self) -> Result<AttachmentIterator<'a>> {
        let key = try!(self.item_key());
        Ok(AttachmentIterator {
            inner: self.attachments.iter(),
            atts: self.atts,
            key: Rc::new(key),
            overview: self.overview.clone(),
        })
    }
}

static BANDS: &'static [u8; 16] = b"0123456789ABCDEF";

// Load the items given the containing path
pub fn read_items(p: &Path, master: Rc<MasterKey>) -> Result<HashMap<Uuid, ItemData>> {
    let mut map = HashMap::new();
    for x in BANDS.iter() {
        let name = format!("band_{}.js", *x as char);
        let path = p.join(name);
        let items = try!(read_band(&path, master.clone()));
        map.extend(items);
    }

    Ok(map)
}

fn read_band(p: &Path, master: Rc<MasterKey>) -> Result<HashMap<Uuid, ItemData>> {
    let mut f = match File::open(p) {
        Err(ref e) if e.kind() == ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(From::from(e)),
        Ok(x) => x,
    };
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    let json_str = s.trim_left_matches("ld(").trim_right_matches(");");

    let mut items: HashMap<Uuid, ItemData> = try!(serde_json::from_str(json_str));
    let valid_items = items.drain()
        .filter(|&(_, ref i)| i.verify(master.verification()).is_ok())
        .collect();
    Ok(valid_items)
}

pub fn item_from_data<'a>(d: &ItemData, atts: &'a HashMap<Uuid, (AttachmentData, PathBuf)>, master: Rc<MasterKey>, overview: Rc<OverviewKey>) -> Result<Item<'a>> {
    Item::from_item_data(d, atts, master, overview)
}

pub struct ItemIterator<'a> {
    pub inner: HashMapValues<'a, Uuid, ItemData>,
    pub master: Rc<MasterKey>,
    pub overview: Rc<OverviewKey>,
    pub attachments: &'a HashMap<Uuid, (AttachmentData, PathBuf)>,
}

impl<'a> Iterator for ItemIterator<'a> {
    type Item = Item<'a>;

    fn next(&mut self) -> Option<Item<'a>> {
        self.inner.next().and_then(|item_data| {
            item_from_data(item_data, self.attachments, self.master.clone(), self.overview.clone()).ok()
        })
    }
}
