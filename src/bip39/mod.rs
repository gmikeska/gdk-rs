//! BIP39 Mnemonic code for generating deterministic keys.

pub mod wordlist;

use self::wordlist::WORDLIST;
use crate::Result;
use hmac::Hmac;
use sha2::{Digest, Sha512, Sha256};

pub struct Mnemonic {
    phrase: String,
}

impl Mnemonic {
    pub fn from_entropy(entropy: &[u8]) -> Result<Self> {
        let entropy_bits = entropy.len() * 8;
        if entropy_bits < 128 || entropy_bits > 256 || entropy_bits % 32 != 0 {
            return Err(crate::GdkError::InvalidInput("Invalid entropy length".to_string()));
        }

        let checksum_len = entropy_bits / 32;
        let hash = Sha256::digest(entropy);
        let checksum = hash[0];

        let mut bits = Vec::with_capacity(entropy_bits + checksum_len);
        for byte in entropy {
            for i in 0..8 {
                bits.push((byte >> (7 - i)) & 1 == 1);
            }
        }
        for i in 0..checksum_len {
            bits.push((checksum >> (7 - i)) & 1 == 1);
        }

        let mut words = Vec::new();
        for chunk in bits.chunks(11) {
            let mut index = 0;
            for (i, &bit) in chunk.iter().enumerate() {
                if bit {
                    index += 1 << (10 - i);
                }
            }
            words.push(WORDLIST[index]);
        }

        let phrase = words.join(" ");
        Ok(Mnemonic { phrase })
    }

    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let words: Vec<&str> = phrase.split(' ').collect();
        if words.len() != 12 && words.len() != 24 {
            return Err(crate::GdkError::InvalidInput("Invalid word count".to_string()));
        }

        // This is a placeholder, a full implementation would do the reverse
        // of from_entropy, including checksum validation.
        Ok(Mnemonic { phrase: phrase.to_string() })
    }
}

pub struct Seed(pub [u8; 64]);

impl Seed {
    pub fn new(mnemonic: &Mnemonic, password: &str) -> Self {
        let salt = format!("mnemonic{}", password);
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2::<Hmac<Sha512>>(
            mnemonic.phrase().as_bytes(),
            salt.as_bytes(),
            2048, // BIP39 iteration count
            &mut seed,
        );
        Seed(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_from_entropy() {
        // BIP39 test vector
        let entropy = hex::decode("00000000000000000000000000000000").unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(mnemonic.phrase(), expected_phrase);
    }

    #[test]
    fn test_seed_generation() {
        // BIP39 test vector
        let mnemonic = Mnemonic { phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string() };
        let seed = Seed::new(&mnemonic, "TREZOR");
        let expected_seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        assert_eq!(hex::encode(seed.0), expected_seed_hex);
    }
}
