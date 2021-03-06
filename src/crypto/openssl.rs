// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! The OpenSSL implementation of our crypto functions

use super::super::{Result, HmacKey};
use openssl::symm;
use openssl::sign;
use openssl::pkey::PKey;
use openssl::hash;
use openssl::hash::MessageDigest;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::error::ErrorStack;

pub type Error = ErrorStack;

impl From<ErrorStack> for super::super::Error {
    fn from(e: ErrorStack) -> Self {
        super::super::Error::Crypto(e)
    }
}


pub fn pbkdf2(pw: &[u8], salt: &[u8], iterations: usize) -> Result<[u8; 64]> {
    let mut derived = [0u8; 64];
    pbkdf2_hmac(pw, salt, iterations, MessageDigest::sha512(), &mut derived)?;

    Ok(derived)
}

pub fn hash_sha512(data: &[u8]) -> Result<Vec<u8>> {
    match hash::hash(MessageDigest::sha512(), data) {
        Ok(x) => Ok(x.to_vec()),
        Err(e) => Err(From::from(e)),
    }
}


pub fn decrypt_data(data: &[u8], decrypt_key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let t = symm::Cipher::aes_256_cbc();
    let mut crypter = symm::Crypter::new(t, symm::Mode::Decrypt, decrypt_key, Some(iv))?;
    crypter.pad(false);
    let mut decrypted = vec![0u8; data.len()+ t.block_size()];
    let count = crypter.update(data, &mut decrypted[..])?;
    let rest = crypter.finalize(&mut decrypted[count..])?;

    decrypted.truncate(count + rest);
    Ok(decrypted)
}

pub fn verify_data(data: &[u8], hmac_key: &[u8]) -> Result<bool> {
    let mac = &data[data.len() - 32..];
    let pkey = PKey::hmac(hmac_key)?;
    let mut signer = sign::Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(&data[..data.len() - 32])?;
    let computed_hmac = signer.sign_to_vec()?;

    Ok(computed_hmac.as_slice() == mac)
}

pub struct HMAC<'b> {
    signer: Box<sign::Signer<'b>>,
}

pub fn hmac<F>(key: &HmacKey, cb: F) -> Result<Vec<u8>>
    where F: Fn(&mut HMAC) -> Result<()> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Box::new(sign::Signer::new(MessageDigest::sha256(), &pkey)?);

    // Move the value into and out of HMAC so the borrow checker is happy with us.
    let mut hmac = HMAC { signer };
    cb(&mut hmac)?;
    signer = hmac.signer;

    match signer.sign_to_vec() {
        Ok(x) => Ok(x),
        Err(e) => Err(From::from(e)),
    }
}

impl<'b> HMAC<'b> {
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        match self.signer.update(data) {
            Ok(_) => Ok(()),
            Err(e) => Err(From::from(e)),
        }
    }
}
