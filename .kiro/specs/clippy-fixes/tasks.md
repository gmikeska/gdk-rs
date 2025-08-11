# Implementation Plan

- [ ] 1. Fix format string inefficiencies in tor.rs
  - Convert all `format!("text {}", variable)` patterns to `format!("text {variable}")` in src/tor.rs
  - Update log statements to use direct variable interpolation
  - Fix useless format usage by replacing with `.to_string()` where appropriate
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 2. Fix format string inefficiencies in lib.rs and other core files
  - Convert format strings in src/lib.rs to use direct variable interpolation
  - Fix unnecessary Debug formatting in log statements
  - Update format strings in src/assets.rs, src/network.rs, and other core modules
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 3. Add error documentation to public Result-returning functions
  - Add `# Errors` sections to all public functions in src/lib.rs that return Result
  - Add error documentation to public functions in src/utils/ modules
  - Add error documentation to public functions in src/primitives/ modules
  - _Requirements: 2.1, 2.2, 2.3_

- [ ] 4. Add panic documentation to public functions that may panic
  - Add `# Panics` sections to functions that use unwrap, expect, or panic
  - Document panic conditions for array indexing and arithmetic operations
  - Add panic documentation to assertion-heavy functions
  - _Requirements: 3.1, 3.2, 3.3_

- [ ] 5. Optimize GdkError enum size by boxing large variants
  - Create ErrorDetails struct to hold common error fields
  - Refactor GdkError enum to use Box<ErrorDetails> for all variants
  - Update error constructor methods to work with boxed structure
  - Add accessor methods for boxed error fields
  - _Requirements: 4.1, 4.2, 4.3_

- [ ] 6. Add must_use attributes to functions returning useful values
  - Add `#[must_use]` attribute to functions in src/tor.rs that return bool or important values
  - Add must_use attributes to utility functions in src/utils/ modules
  - Add must_use attributes to primitive type methods that return computed values
  - _Requirements: 6.1, 6.2, 6.3_

- [ ] 7. Mark appropriate functions as const
  - Convert simple utility functions to `const fn` where possible
  - Mark pure calculation functions as const in src/utils/crypto.rs
  - Update primitive type methods to be const where appropriate
  - _Requirements: 5.1, 5.2, 5.3_

- [ ] 8. Remove redundant code patterns
  - Combine identical match arms in src/error.rs and other files
  - Remove redundant else blocks after early returns
  - Eliminate unnecessary continue statements in loops
  - _Requirements: 7.1, 7.2, 7.3_

- [ ] 9. Fix async function usage
  - Remove async modifier from functions with no await statements in src/session.rs
  - Remove async from functions in src/api/transactions.rs that don't need it
  - Remove async from hardware wallet functions in src/hw.rs that are synchronous
  - _Requirements: 8.1, 8.2, 8.3_

- [ ] 10. Fix mutable reference usage
  - Change `&mut self` to `&self` in src/auth.rs functions that don't mutate
  - Update function signatures to use immutable references where possible
  - Ensure function behavior remains unchanged after reference type changes
  - _Requirements: 9.1, 9.2, 9.3_

- [ ] 11. Improve numeric literal readability
  - Add separators to long numeric literals in src/primitives/transaction.rs
  - Format hex literals with appropriate separators for readability
  - Update other numeric constants throughout the codebase
  - _Requirements: 10.1, 10.2, 10.3_

- [ ] 12. Fix variable naming conflicts
  - Rename similar variables like `state` and `stats` in src/network.rs to be more distinct
  - Update variable names to improve code clarity
  - Ensure renamed variables maintain their original functionality
  - _Requirements: 11.1, 11.2, 11.3_

- [ ] 13. Fix file extension comparisons
  - Replace case-sensitive `.ends_with(".onion")` with case-insensitive Path-based comparison in src/tor.rs
  - Update other file extension checks to be case-insensitive where appropriate
  - Ensure file handling logic remains correct after changes
  - _Requirements: 12.1, 12.2, 12.3_

- [ ] 14. Fix unsafe type casting
  - Replace `as u8` casts with `try_from` conversions in src/tor.rs
  - Add proper error handling for potentially lossy numeric conversions
  - Update other unsafe casts throughout the codebase to use safe alternatives
  - _Requirements: 13.1, 13.2, 13.3_

- [ ] 15. Optimize temporary value lifetimes
  - Fix significant drop tightening issues in src/tor.rs by reducing temporary lifetimes
  - Optimize lock usage to minimize contention
  - Ensure resource management improvements don't change functionality
  - _Requirements: 14.1, 14.2, 14.3_

- [ ] 16. Fix useless vector usage
  - Replace `vec![]` with array literals where appropriate in src/assets.rs
  - Update other unnecessary vector allocations to use more efficient alternatives
  - Ensure data structure changes maintain the same interface
  - _Requirements: 7.1, 7.2, 7.3_

- [ ] 17. Fix hidden lifetime parameters
  - Update type definitions to use explicit lifetime parameters where required
  - Fix deprecated lifetime syntax throughout the codebase
  - Ensure lifetime changes don't break existing APIs
  - _Requirements: 15.1, 15.2, 15.3_

- [ ] 18. Add missing trait implementations
  - Add Debug trait implementations where needed for clippy compliance
  - Add Clone trait implementations for types that should be cloneable
  - Ensure new trait implementations follow standard conventions
  - _Requirements: 15.1, 15.2, 15.3_

- [ ] 19. Fix structure name repetition
  - Remove unnecessary structure name repetition in constructor calls
  - Use field init shorthand where variable names match field names
  - Update struct initialization patterns throughout the codebase
  - _Requirements: 7.1, 7.2, 7.3_

- [ ] 20. Run comprehensive clippy validation
  - Execute `cargo clippy --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery -W rust-2018-idioms`
  - Verify that all warnings and errors have been resolved
  - Fix any remaining issues discovered during final validation
  - Run tests to ensure all functionality remains intact after changes
  - _Requirements: 15.1, 15.2, 15.3_