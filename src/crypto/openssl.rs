/// The OpenSSL implementation of our crypts functions

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
    try!(pbkdf2_hmac(pw, salt, iterations, MessageDigest::sha512(), &mut derived));

    Ok(derived)
}

pub fn hash_sha512(data: &[u8]) -> Result<Vec<u8>> {
    match hash::hash(MessageDigest::sha512(), data) {
        Ok(x) => Ok(x),
        Err(e) => Err(From::from(e)),
    }
}


pub fn decrypt_data(data: &[u8], decrypt_key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let t = symm::Cipher::aes_256_cbc();
    let mut crypter = try!(symm::Crypter::new(t, symm::Mode::Decrypt, decrypt_key, Some(iv)));
    crypter.pad(false);
    let mut decrypted = vec![0u8; data.len()+ t.block_size()];
    let count = try!(crypter.update(data, &mut decrypted[..]));
    let rest = try!(crypter.finalize(&mut decrypted[count..]));

    decrypted.truncate(count + rest);
    Ok(decrypted)
}

pub fn verify_data(data: &[u8], hmac_key: &[u8]) -> Result<bool> {
    let mac = &data[data.len() - 32..];
    let pkey = try!(PKey::hmac(hmac_key));
    let mut signer = try!(sign::Signer::new(MessageDigest::sha256(), &pkey));
    try!(signer.update(&data[..data.len() - 32]));
    let computed_hmac = try!(signer.finish());

    Ok(computed_hmac.as_slice() == mac)
}

pub struct HMAC<'b> {
    signer: Box<sign::Signer<'b>>,
}

pub fn hmac<F>(key: &HmacKey, cb: F) -> Result<Vec<u8>>
    where F: Fn(&mut HMAC) -> Result<()> {
    let pkey = try!(PKey::hmac(key));
    let mut signer = Box::new(try!(sign::Signer::new(MessageDigest::sha256(), &pkey)));

    // Move the value into and out of HMAC so the borrow checker is happy with us.
    let mut hmac = HMAC { signer: signer };
    try!(cb(&mut hmac));
    signer = hmac.signer;

    match signer.finish() {
        Ok(x) => Ok(x),
        Err(e) => Err(From::from(e)),
    }
}

impl<'b> HMAC<'b> {
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        match self.signer.update(data) {
            Ok(x) => Ok(x),
            Err(e) => Err(From::from(e)),
        }
    }
}
