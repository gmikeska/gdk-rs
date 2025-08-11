# Design Document

## Overview

This design addresses the systematic resolution of compilation errors in the GDK Rust library's test suite. The errors fall into several categories: missing method implementations in core types, missing trait implementations, and unused import warnings. The solution involves implementing missing methods with appropriate functionality while maintaining compatibility with the existing codebase architecture.

## Architecture

The fix strategy follows a layered approach:

1. **Core Type Extensions**: Add missing methods to `LoginCredentials`, `TransactionBuilder`, and `Script` types
2. **Trait Implementation**: Add required trait implementations (`Debug`, `Clone`) to support testing
3. **Import Cleanup**: Remove unused imports to eliminate warnings
4. **Test Compatibility**: Ensure all implementations provide meaningful functionality for test scenarios

## Components and Interfaces

### LoginCredentials Extensions

The `LoginCredentials` struct in `src/protocol.rs` needs additional constructor methods:

- `from_mnemonic(mnemonic: String, passphrase: Option<String>) -> Self`
- `from_pin(pin: String, pin_data: Vec<u8>) -> Self` 
- `from_watch_only_user(username: String, password: String) -> Self`

These methods will create appropriate `LoginCredentials` instances by mapping the input parameters to the existing struct fields.

### TransactionBuilder Extensions

The `TransactionBuilder` struct in `src/transaction_builder.rs` needs a comprehensive API for test compatibility:

**Builder Pattern Methods:**
- `add_input(outpoint: OutPoint, script_sig: Script) -> ()`
- `add_input_with_sequence(outpoint: OutPoint, script_sig: Script, sequence: u32) -> ()`
- `add_output(value: u64, script_pubkey: Script) -> ()`
- `add_witness(input_index: usize, witness_data: Vec<Vec<u8>>) -> Result<()>`

**Configuration Methods:**
- `set_fee_rate(fee_rate: u64) -> ()`
- `set_lock_time(lock_time: u32) -> ()`
- `set_version(version: i32) -> ()`

**Accessor Methods:**
- `network() -> Network`
- `inputs() -> &[TxIn]`
- `outputs() -> &[TxOut]`
- `fee_rate() -> Option<u64>`
- `lock_time() -> u32`

**Utility Methods:**
- `build() -> Result<Transaction>`
- `clear() -> ()`
- `reset(network: Network) -> ()`
- `estimate_size() -> u64`
- `estimate_vsize() -> u64`

**Internal State:**
The builder will maintain internal state for inputs, outputs, fee rate, lock time, version, and witness data to support the test scenarios.

### Script Extensions

The `Script` struct in `src/primitives/script.rs` needs:

- `new_op_return(data: &[u8]) -> Self`: Create OP_RETURN scripts for data storage

### Trait Implementations

**Debug Trait:**
- Add `#[derive(Debug)]` or manual `Debug` implementation for `TransactionBuilder`

**Clone Trait:**
- Add `#[derive(Clone)]` or manual `Clone` implementation for `TransactionBuilder`

## Data Models

### TransactionBuilder Internal State

```rust
pub struct TransactionBuilder {
    network: Network,
    fee_estimates: FeeEstimate,
    // New fields for test compatibility:
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    witnesses: HashMap<usize, Vec<Vec<u8>>>,
    fee_rate: Option<u64>,
    lock_time: u32,
    version: i32,
}
```

### LoginCredentials Constructor Parameters

The constructor methods will map parameters to the existing struct fields:
- `mnemonic` field stores the mnemonic phrase
- `bip39_passphrase` field stores optional passphrase
- `password` field stores PIN or user password as appropriate

## Error Handling

### Method Signatures and Error Types

- Methods that can fail (like `add_witness`, `build`) return `Result<T>` with appropriate `GdkError` variants
- Index-based operations validate bounds and return errors for invalid indices
- Transaction building validates inputs/outputs and returns errors for insufficient data

### Validation Strategy

- Input validation ensures outpoints, scripts, and amounts are valid
- Witness data validation checks input index bounds
- Transaction building validates that inputs and outputs are present before building

## Testing Strategy

### Compatibility Testing

- All new methods must pass existing test scenarios without modification
- Method implementations should provide realistic behavior for test assertions
- Error cases should be handled gracefully with appropriate error messages

### Implementation Testing

- Unit tests for each new method to verify correct behavior
- Integration tests to ensure compatibility with existing transaction building flow
- Error condition testing for edge cases and invalid inputs

### Regression Testing

- Ensure existing functionality remains unchanged
- Verify that the comprehensive transaction builder API still works correctly
- Test that fee estimation and coin selection continue to function

## Implementation Notes

### Backward Compatibility

The design maintains full backward compatibility by:
- Adding new methods without modifying existing signatures
- Preserving existing behavior of the comprehensive transaction building API
- Using the existing internal state where possible

### Test-Focused Design

The implementation prioritizes test compatibility:
- Simple, direct method implementations that satisfy test expectations
- Reasonable default values and behaviors for test scenarios
- Clear error messages for debugging test failures

### Performance Considerations

- New methods use efficient data structures (Vec, HashMap) for internal state
- Minimal overhead for accessor methods
- Lazy evaluation where appropriate (e.g., transaction building only when requested)