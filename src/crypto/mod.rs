/// This modules wraps the different crypto implementations so we e.g. use
/// CommonCrypto on macOS instead of OpenSSL.

mod openssl;
pub use self::openssl::{verify_data, decrypt_data, hmac, hash_sha512, pbkdf2, Error};
