// Copyright 2016 OPVault Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::{Path, PathBuf};
use std::fs;
use std::io::SeekFrom;
use std::io::prelude::*;
use std::collections::HashMap;

use rustc_serialize::base64::FromBase64;
use rustc_serialize::json;

use super::{Result, Uuid, DerivedKey};
use super::{opcldat, opdata01};

#[derive(Debug, RustcDecodable)]
#[allow(non_snake_case)]
pub struct AttachmentData {
    itemUUID: Uuid,
    contentsSize: u64,
    external: Option<bool>,
    updatedAt: i64,
    txTimestamp: i64,
    overview: String,
    createdAt: i64,
    uuid: Uuid,
}

#[derive(Debug)]
pub struct Attachment {
    pub item: Uuid,
    pub contents_size: u64,
    pub external: Option<bool>,
    pub updated_at: i64,
    pub tx_timestamp: i64,
    pub overview: Vec<u8>,
    pub created_at: i64,
    pub uuid: Uuid,
    path: PathBuf,
}

impl Attachment {
    fn from_attachment_data(d: AttachmentData, p: PathBuf) -> Result<Attachment> {
        let overview = try!(d.overview.from_base64());

        Ok(Attachment {
            item: d.itemUUID,
            contents_size: d.contentsSize,
            external: d.external,
            updated_at: d.updatedAt,
            tx_timestamp: d.txTimestamp,
            overview: overview,
            created_at: d.createdAt,
            uuid: d.uuid,
            path: p,
        })
    }

    /// Decrypt the attachment's overview data
    pub fn decrypt_overview(&self, key: &DerivedKey) -> Result<Vec<u8>> {
        opdata01::decrypt(&self.overview[..], &key.encrypt, &key.hmac)
    }

    /// Decrypt the attachment's icon
    pub fn decrypt_icon(&self, key: &DerivedKey) -> Result<Vec<u8>> {
        // The content is just after the metadata, so we need to open the file
        // again and figure out where things are.
        let mut f = try!(fs::File::open(&self.path));
        let metadata = try!(opcldat::read_header(&mut f));

        let icon_offset = 16 /* header */ + metadata.metadata_size;

        let mut icon_data = vec![0u8; metadata.icon_size as usize];
        try!(f.seek(SeekFrom::Start(icon_offset as u64)));
        try!(f.read_exact(&mut icon_data));
        opdata01::decrypt(&icon_data[..], &key.encrypt, &key.hmac)
    }

    /// Decrypt the attachment's content
    pub fn decrypt_content(&self, key: &DerivedKey) -> Result<Vec<u8>> {
        // The content is just after the metadata, so we need to open the file
        // again and figure out where things are.
        let mut f = try!(fs::File::open(&self.path));
        let metadata = try!(opcldat::read_header(&mut f));

        let content_offset = 16 /* header */ + (metadata.metadata_size as usize) + (metadata.icon_size) as usize;

        let mut content_data = Vec::new();
        try!(f.seek(SeekFrom::Start(content_offset as u64)));
        try!(f.read_to_end(&mut content_data));
        opdata01::decrypt(&content_data[..], &key.encrypt, &key.hmac)
    }
}

pub fn read_attachments(p: &Path) -> Result<HashMap<Uuid, Attachment>> {
    let mut map = HashMap::new();
    for entry in try!(fs::read_dir(p)) {
        let entry = try!(entry);
        let file_type = try!(entry.file_type());
        if file_type.is_dir() {
            continue;
        }

        let filename = entry.file_name();
        if let Some(name) = filename.to_str() {
            if name.ends_with(".attachment") {
                let attachment = try!(read_attachment(&entry.path()));
                map.insert(attachment.uuid, attachment);
            }
        }
    }

    Ok(map)
}

pub fn read_attachment(p: &Path) -> Result<Attachment> {
    let mut f = try!(fs::File::open(p));

    let metadata = try!(opcldat::read_header(&mut f));
    let mut json_data = vec![0u8; metadata.metadata_size as usize];
    try!(f.read_exact(&mut json_data));
    let json_str = try!(String::from_utf8(json_data));
    let data = try!(json::decode(&json_str));
    match Attachment::from_attachment_data(data, p.to_path_buf()) {
        Ok(x) => Ok(x),
        Err(e) => Err(From::from(e)),
    }
}
