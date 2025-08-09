//! Bitcoin hashing utilities.

use sha2::{Digest, Sha256};
use ripemd::{Ripemd160};

/// A standard Hash160 is RIPEMD160(SHA256(data)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_hash = Sha256::digest(data);
    let mut ripemd160 = Ripemd160::new();
    ripemd160.update(sha256_hash);
    ripemd160.finalize().into()
}

/// A standard Double-SHA256 is SHA256(SHA256(data)).
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}
