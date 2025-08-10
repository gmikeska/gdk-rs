use gdk_rs::*;
use gdk_rs::utils::*;

#[test]
fn test_generate_mnemonic() {
    let mnemonic = generate_mnemonic().unwrap();
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert_eq!(words.len(), 12); // Placeholder returns 12 words
}
