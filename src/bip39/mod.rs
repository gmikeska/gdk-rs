//! BIP39 Mnemonic code for generating deterministic keys.

pub mod wordlist;

use self::wordlist::WORDLIST;
use crate::Result;
use hmac::Hmac;
use sha2::{Digest, Sha512, Sha256};

#[derive(Debug)]
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
        log::debug!("Parsing phrase: {}", phrase);
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let num_words = words.len();

        if num_words != 12 && num_words != 24 {
            return Err(crate::GdkError::InvalidInput(format!("Invalid word count: {}", num_words)));
        }

        let mut bits = Vec::with_capacity(num_words * 11);
        for word in words {
            log::debug!("Searching for word: '{}'", word);
            match WORDLIST.binary_search(&word) {
                Ok(index) => {
                    log::debug!("Found word {} at index {}", word, index);
                    for i in 0..11 {
                        bits.push((index >> (10 - i)) & 1 == 1);
                    }
                }
                Err(e) => {
                    log::error!("Word not found: '{}', search error: {:?}", word, e);
                    return Err(crate::GdkError::InvalidInput(format!("Invalid word: {}", word)));
                }
            }
        }

        let checksum_len = num_words / 3;
        let entropy_len = num_words * 11 - checksum_len;
        let entropy_bytes_len = entropy_len / 8;

        let mut entropy = vec![0u8; entropy_bytes_len];
        for i in 0..entropy_len {
            if bits[i] {
                entropy[i / 8] |= 1 << (7 - (i % 8));
            }
        }

        let hash = Sha256::digest(&entropy);
        let checksum = hash[0];

        log::debug!("Calculated checksum byte: {:08b}", checksum);

        for i in 0..checksum_len {
            let expected_bit = bits[entropy_len + i];
            let actual_bit = (checksum >> (7 - i)) & 1 == 1;
            log::debug!("Checksum bit {}: expected={}, actual={}", i, expected_bit, actual_bit);
            if expected_bit != actual_bit {
                return Err(crate::GdkError::InvalidInput("Invalid checksum".to_string()));
            }
        }

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

    #[test]
    fn test_from_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase);
        assert!(mnemonic.is_ok());

        let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"; // 11 words
        assert!(Mnemonic::from_phrase(invalid_phrase).is_err());

        let invalid_checksum = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        let result = Mnemonic::from_phrase(invalid_checksum);
        if result.is_ok() {
            panic!("Should have failed on invalid word, but got Ok({:?})", result.unwrap());
        }
    }

    #[test]
    fn test_wordlist_is_sorted() {
        let mut sorted_list = wordlist::WORDLIST;
        sorted_list.sort_unstable();
        assert_eq!(wordlist::WORDLIST, sorted_list, "BIP39 wordlist is not sorted");
    }
}
