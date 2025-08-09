//! Bitcoin hashing utilities.

use sha2::{Digest, Sha256};
use ripemd::{Ripemd160};
use serde::{Deserialize, Serialize};

/// A 256-bit hash
pub type Hash256 = [u8; 32];

/// A 160-bit hash
pub type Hash160 = [u8; 20];

/// A standard Hash160 is RIPEMD160(SHA256(data)).
pub fn hash160(data: &[u8]) -> Hash160 {
    let sha256_hash = Sha256::digest(data);
    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(sha256_hash);
    ripemd160.finalize().into()
}

/// A standard Double-SHA256 is SHA256(SHA256(data)).
pub fn sha256d(data: &[u8]) -> Hash256 {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Single SHA256 hash
pub fn sha256(data: &[u8]) -> Hash256 {
    Sha256::digest(data).into()
}
