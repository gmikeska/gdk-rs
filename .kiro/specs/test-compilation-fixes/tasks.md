# Implementation Plan

- [ ] 1. Implement LoginCredentials constructor methods
  - Add `from_mnemonic`, `from_pin`, and `from_watch_only_user` methods to LoginCredentials struct
  - Map input parameters to existing struct fields appropriately
  - _Requirements: 2.1, 2.2, 2.3, 2.4_

- [ ] 2. Add internal state fields to TransactionBuilder
  - Add fields for inputs, outputs, witnesses, fee_rate, lock_time, and version to TransactionBuilder struct
  - Initialize new fields in the constructor with appropriate default values
  - _Requirements: 3.1, 3.2, 3.3_

- [ ] 3. Implement TransactionBuilder input management methods
  - Code `add_input` method to add TxIn to internal inputs vector
  - Code `add_input_with_sequence` method with custom sequence number
  - Implement `inputs()` accessor method to return reference to inputs vector
  - _Requirements: 3.1, 3.2_

- [ ] 4. Implement TransactionBuilder output management methods
  - Code `add_output` method to add TxOut to internal outputs vector
  - Implement `outputs()` accessor method to return reference to outputs vector
  - _Requirements: 3.1, 3.2_

- [ ] 5. Implement TransactionBuilder witness management methods
  - Code `add_witness` method to store witness data for specific input index
  - Validate input index bounds and return appropriate errors
  - _Requirements: 3.5_

- [ ] 6. Implement TransactionBuilder configuration methods
  - Code `set_fee_rate` method to store fee rate in internal state
  - Code `set_lock_time` method to store lock time value
  - Code `set_version` method to store transaction version
  - Implement corresponding accessor methods: `fee_rate()`, `lock_time()`
  - _Requirements: 3.3_

- [ ] 7. Implement TransactionBuilder network accessor method
  - Code `network()` method to return the builder's network field
  - _Requirements: 3.2_

- [ ] 8. Implement TransactionBuilder utility methods
  - Code `clear()` method to reset all internal state vectors and optional values
  - Code `reset(network)` method to clear state and update network
  - _Requirements: 3.3_

- [ ] 9. Implement TransactionBuilder build method
  - Code `build()` method to construct Transaction from internal state
  - Validate that inputs and outputs are present before building
  - Apply witness data to transaction inputs where available
  - Set transaction version and lock time from internal state
  - _Requirements: 3.1, 3.2, 3.5_

- [ ] 10. Implement TransactionBuilder estimation methods
  - Code `estimate_size()` method to calculate transaction byte size
  - Code `estimate_vsize()` method to calculate virtual transaction size
  - Update existing `estimate_fee()` method to work without parameters for test compatibility
  - _Requirements: 3.4_

- [ ] 11. Add trait implementations to TransactionBuilder
  - Add `Debug` trait implementation or derive macro
  - Add `Clone` trait implementation or derive macro
  - _Requirements: 5.1, 5.2_

- [ ] 12. Implement Script::new_op_return method
  - Code `new_op_return` method to create OP_RETURN scripts with data payload
  - Follow Bitcoin script standards for OP_RETURN construction
  - _Requirements: 4.1_

- [ ] 13. Clean up unused imports in test files
  - Remove unused imports from hw_test.rs to eliminate warnings
  - Preserve all necessary imports for test functionality
  - _Requirements: 6.1, 6.2, 6.3_

- [ ] 14. Verify compilation and run tests
  - Compile the project with `cargo test --all-features --all` to verify all errors are resolved
  - Run tests to ensure implementations work correctly with existing test scenarios
  - Fix any remaining compilation issues or test failures
  - _Requirements: 1.1, 1.2, 1.3_