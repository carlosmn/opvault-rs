// Copyright 2016 opvault-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This module wraps the different crypto implementations so we e.g. use
//! CommonCrypto on macOS instead of OpenSSL.

mod openssl;
pub use self::openssl::{verify_data, decrypt_data, hmac, hash_sha512, pbkdf2, Error};
