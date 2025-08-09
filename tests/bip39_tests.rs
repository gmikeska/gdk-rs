use gdk_rs::bip39::{Mnemonic, Seed};
use hex;

#[test]
fn test_from_entropy() {
    let entropy = hex::decode("00000000000000000000000000000000").unwrap();
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    let expected_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert_eq!(mnemonic.phrase(), expected_phrase);
}

#[test]
fn test_seed_generation() {
    let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
    let seed = Seed::new(&mnemonic, "TREZOR");
    let expected_seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    assert_eq!(hex::encode(seed.0), expected_seed_hex);
}

#[test]
fn test_from_phrase_valid() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_phrase(phrase);
    assert!(mnemonic.is_ok());
}

#[test]
fn test_from_phrase_invalid_word_count() {
    let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"; // 11 words
    assert!(Mnemonic::from_phrase(invalid_phrase).is_err());
}

#[test]
fn test_from_phrase_invalid_checksum() {
    // A valid 12-word phrase where the last word is changed, which MUST invalidate the checksum.
    let invalid_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon acid";
    let result = Mnemonic::from_phrase(invalid_checksum);
    assert!(result.is_err(), "Should have failed on invalid checksum");
}
