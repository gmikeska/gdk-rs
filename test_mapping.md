# Test File Mapping for GDK-RS Refactoring

This document contains the mapping of source files to their new test file names in the `tests/` directory.

## Source File → Test File Mapping

### API Module
- `src/api/mod.rs` → `tests/api_test.rs`
- `src/api/transactions.rs` → `tests/api_transactions_test.rs`

### Core Files
- `src/assets.rs` → `tests/assets_test.rs`
- `src/auth.rs` → `tests/auth_test.rs`
- `src/bip39.rs` → `tests/bip39_test.rs`
- `src/error.rs` → `tests/error_test.rs`
- `src/hw.rs` → `tests/hw_test.rs`
- `src/lib.rs` → `tests/lib_test.rs`
- `src/network.rs` → `tests/network_test.rs`
- `src/notifications.rs` → `tests/notifications_test.rs`
- `src/protocol.rs` → `tests/protocol_test.rs`
- `src/session.rs` → `tests/session_test.rs`
- `src/transaction_builder.rs` → `tests/transaction_builder_test.rs`
- `src/transaction_signer.rs` → `tests/transaction_signer_test.rs`
- `src/types.rs` → `tests/types_test.rs`
- `src/utils.rs` → `tests/utils_test.rs`
- `src/wallet.rs` → `tests/wallet_test.rs`

### Primitives Module
- `src/primitives/mod.rs` → `tests/primitives_test.rs`
- `src/primitives/address.rs` → `tests/primitives_address_test.rs`
- `src/primitives/bip32.rs` → `tests/primitives_bip32_test.rs`
- `src/primitives/encode.rs` → `tests/primitives_encode_test.rs`
- `src/primitives/hash.rs` → `tests/primitives_hash_test.rs`
- `src/primitives/liquid.rs` → `tests/primitives_liquid_test.rs`
- `src/primitives/psbt.rs` → `tests/primitives_psbt_test.rs`
- `src/primitives/script.rs` → `tests/primitives_script_test.rs`
- `src/primitives/transaction.rs` → `tests/primitives_transaction_test.rs`

### Existing Test Files (to be moved/renamed)
- `src/primitives/script_tests.rs` → `tests/primitives_script_simple_test.rs`
- `src/wallet_address_tests.rs` → `tests/wallet_address_test.rs`
- `src/wallet_simple_tests.rs` → `tests/wallet_simple_test.rs`
- `src/wallet_transaction_tests.rs` → `tests/wallet_transaction_test.rs`

## Notes

1. All test files will be moved to the `tests/` directory at the project root
2. Test files follow the naming convention: `<module_name>_test.rs`
3. For nested modules (like primitives), the parent module name is prefixed
4. Existing test files within `src/` will be moved and renamed to follow the convention
5. Each test file will contain only the tests for its corresponding source file
6. Integration tests that span multiple modules should be placed in separate integration test files

## Checklist for Refactoring

- [ ] Create `tests/` directory if it doesn't exist
- [ ] Move and rename each test file according to the mapping above
- [ ] Update `#[cfg(test)]` blocks in source files to be moved to corresponding test files
- [ ] Update module imports in moved test files
- [ ] Ensure all tests still pass after refactoring
- [ ] Remove test code from source files
- [ ] Update any documentation references to test locations
