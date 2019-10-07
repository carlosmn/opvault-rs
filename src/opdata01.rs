// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io::Cursor;
use std::io::prelude::*;
use std::convert::From;

use super::Result;
use byteorder::{LittleEndian, ReadBytesExt};

use crypto::{verify_data, decrypt_data};

/// The header for this kind of data
static OPDATA_STR: &[u8; 8] = b"opdata01";

#[derive(Debug)]
pub enum OpdataError {
    InvalidHeader,
    InvalidHmac,
}

pub fn decrypt(data: &[u8], decrypt_key: &[u8], mac_key: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(data);

    // The first step is to hash the data (minus the MAC itself)
    if !try!(verify_data(data, mac_key)) {
        return Err(super::Error::OpdataError(OpdataError::InvalidHmac));
    }

    // The data is intact, let's see whether it's well formed now and decrypt
    let mut header = [0u8; 8];
    try!(cursor.read_exact(&mut header));

    if &header != OPDATA_STR {
        return Err(From::from(OpdataError::InvalidHeader));
    }

    let len = try!(cursor.read_u64::<LittleEndian>());
    let iv = &data[16..32];

    let crypt_data = &data[32..data.len()-32];

    let decrypted = try!(decrypt_data(crypt_data, decrypt_key, iv));
    let unpadded: Vec<u8> = decrypted[crypt_data.len()-(len as usize)..].into();

    Ok(unpadded)
}
