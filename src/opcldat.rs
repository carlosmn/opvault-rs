// Copyright 2016 OPVault Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io::prelude::*;

use super::{Result, Error};
use byteorder::{LittleEndian, ReadBytesExt};

const OPCLDAT_STR: &[u8] = b"OPCLDAT";

#[derive(Debug)]
pub struct Opcldat {
    pub version: u8,
    pub metadata_size: u16,
    pub icon_size: u32,
}

pub fn read_header<R: Read>(r: &mut R) -> Result<Opcldat> {
    let mut header = [0u8; 7];
    r.read_exact(&mut header)?;

    if header != OPCLDAT_STR {
        return Err(Error::OpcldatError);
    }

    let version = r.read_u8()?;
    let metadata_size = r.read_u16::<LittleEndian>()?;
    let _junk = r.read_u16::<LittleEndian>()?;
    let icon_size = r.read_u32::<LittleEndian>()?;

    Ok(Opcldat {
        version,
        metadata_size,
        icon_size,
    })
}
