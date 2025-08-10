#!/bin/bash

# Process remaining files
echo "Processing remaining test files..."

# Define the files that still need processing
files=(
    "src/primitives/address.rs"
    "src/primitives/bip32.rs"
    "src/primitives/script.rs"
    "src/api/transactions.rs"
    "src/assets.rs"
    "src/bip39.rs"
    "src/hw.rs"
    "src/transaction_signer.rs"
)

# Function to get test file name
get_test_file_name() {
    local src_file=$1
    # Remove src/ prefix and .rs suffix
    local path=${src_file#src/}
    path=${path%.rs}
    # Replace / with _
    path=${path//\//_}
    echo "tests/${path}_test.rs"
}

# Process each file
for file in "${files[@]}"; do
    echo "Processing: $file"
    test_file=$(get_test_file_name "$file")
    echo "Test file will be: $test_file"
done
