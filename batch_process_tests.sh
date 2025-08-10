#!/bin/bash

# Function to create test file for a module
create_test_file() {
    local src_file=$1
    local test_file=$2
    local module_path=$3
    
    echo "Creating test file: $test_file"
    
    # Extract test module content and process it
    echo "use gdk_rs::*;" > "$test_file"
    echo "use gdk_rs::${module_path}::*;" >> "$test_file"
    
    # Add any necessary imports based on the module
    if [[ "$src_file" == *"bip32"* ]]; then
        echo "use std::str::FromStr;" >> "$test_file"
        echo "use secp256k1::{SecretKey, PublicKey};" >> "$test_file"
    fi
    
    if [[ "$src_file" == *"script"* ]]; then
        echo "use gdk_rs::primitives::hash::hash160;" >> "$test_file"
    fi
    
    if [[ "$src_file" == *"bip39"* ]]; then
        echo "use std::collections::HashSet;" >> "$test_file"
    fi
    
    echo "" >> "$test_file"
    echo "// Tests extracted from $src_file" >> "$test_file"
}

# Process each remaining file
create_test_file "src/primitives/bip32.rs" "tests/primitives_bip32_test.rs" "primitives::bip32"
create_test_file "src/primitives/script.rs" "tests/primitives_script_test.rs" "primitives::script"
create_test_file "src/api/transactions.rs" "tests/api_transactions_test.rs" "api::transactions"
create_test_file "src/assets.rs" "tests/assets_test.rs" "assets"
create_test_file "src/bip39.rs" "tests/bip39_test.rs" "bip39"
create_test_file "src/hw.rs" "tests/hw_test.rs" "hw"
create_test_file "src/transaction_signer.rs" "tests/transaction_signer_test.rs" "transaction_signer"

echo "All test file stubs created!"
