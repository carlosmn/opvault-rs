use std::io::Cursor;
use std::io::prelude::*;
use std::convert::From;

use super::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use openssl::symm;
use openssl::pkey::PKey;
use openssl::sign;
use openssl::hash::MessageDigest;

/// The header for this kind of data
static OPDATA_STR: &'static [u8; 8] = b"opdata01";

#[derive(Debug)]
pub enum OpdataError {
    InvalidHeader,
    InvalidHmac,
}

pub fn decrypt(data: &[u8], decrypt_key: &[u8], mac_key: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(data);

    // The first step is to hash the data (minus the MAC itself)
    let mac = &data[data.len() - 32..];

    let pkey = try!(PKey::hmac(mac_key));
    let mut signer = try!(sign::Signer::new(MessageDigest::sha256(), &pkey));
    try!(signer.update(&data[..data.len() - 32]));
    let computed_hmac = try!(signer.finish());

    if computed_hmac.as_slice() != mac {
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

    let t = symm::Cipher::aes_256_cbc();
    let mut crypter = try!(symm::Crypter::new(t, symm::Mode::Decrypt, decrypt_key, Some(iv)));
    crypter.pad(false);
    let mut decrypted = vec![0u8; crypt_data.len()+ t.block_size()];
    let count = try!(crypter.update(crypt_data, &mut decrypted[..]));
    let rest = try!(crypter.finalize(&mut decrypted[count..]));

    decrypted.truncate(count + rest);
    let unpadded: Vec<u8> = decrypted[crypt_data.len()-(len as usize)..].into();

    Ok(unpadded)
}
