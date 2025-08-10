//! Performance benchmarks for cryptographic operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gdk_rs::utils::crypto::*;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use rand::{thread_rng, RngCore};

fn bench_hash_functions(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_functions");
    
    // Test data of various sizes
    let data_sizes = [32, 256, 1024, 4096, 16384];
    
    for size in data_sizes.iter() {
        let data = vec![0x42u8; *size];
        
        group.bench_with_input(BenchmarkId::new("sha256", size), &data, |b, data| {
            b.iter(|| Hash::sha256(black_box(data)))
        });
        
        group.bench_with_input(BenchmarkId::new("double_sha256", size), &data, |b, data| {
            b.iter(|| Hash::double_sha256(black_box(data)))
        });
        
        group.bench_with_input(BenchmarkId::new("sha512", size), &data, |b, data| {
            b.iter(|| Hash::sha512(black_box(data)))
        });
        
        group.bench_with_input(BenchmarkId::new("ripemd160", size), &data, |b, data| {
            b.iter(|| Hash::ripemd160(black_box(data)))
        });
        
        group.bench_with_input(BenchmarkId::new("hash160", size), &data, |b, data| {
            b.iter(|| Hash::hash160(black_box(data)))
        });
    }
    
    group.finish();
}

fn bench_hmac_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_operations");
    
    let key = b"test_key_for_hmac_benchmarking";
    let data_sizes = [32, 256, 1024, 4096];
    
    for size in data_sizes.iter() {
        let data = vec![0x42u8; *size];
        
        group.bench_with_input(BenchmarkId::new("hmac_sha256", size), &data, |b, data| {
            b.iter(|| Hash::hmac_sha256(black_box(key), black_box(data)).unwrap())
        });
        
        group.bench_with_input(BenchmarkId::new("hmac_sha512", size), &data, |b, data| {
            b.iter(|| Hash::hmac_sha512(black_box(key), black_box(data)).unwrap())
        });
    }
    
    group.finish();
}

fn bench_pbkdf2_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pbkdf2_operations");
    
    let password = b"test_password";
    let salt = b"test_salt";
    let iterations = [1000, 10000, 100000];
    
    for iter_count in iterations.iter() {
        group.bench_with_input(
            BenchmarkId::new("pbkdf2_sha256", iter_count), 
            iter_count, 
            |b, &iter_count| {
                b.iter(|| {
                    KeyDerivation::pbkdf2_sha256(
                        black_box(password), 
                        black_box(salt), 
                        black_box(iter_count), 
                        32
                    )
                })
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("pbkdf2_sha512", iter_count), 
            iter_count, 
            |b, &iter_count| {
                b.iter(|| {
                    KeyDerivation::pbkdf2_sha512(
                        black_box(password), 
                        black_box(salt), 
                        black_box(iter_count), 
                        64
                    )
                })
            }
        );
    }
    
    group.finish();
}

fn bench_secp256k1_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("secp256k1_operations");
    
    let secp = Secp256k1::new();
    let signer = MessageSigning::new();
    
    // Generate test keys
    let private_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    let message = b"test message for signing benchmarks";
    
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let mut key_bytes = [0u8; 32];
            thread_rng().fill_bytes(&mut key_bytes);
            SecretKey::from_slice(black_box(&key_bytes)).unwrap()
        })
    });
    
    group.bench_function("public_key_derivation", |b| {
        b.iter(|| {
            PublicKey::from_secret_key(&secp, black_box(&private_key))
        })
    });
    
    group.bench_function("message_signing", |b| {
        b.iter(|| {
            signer.sign_message(black_box(message), black_box(&private_key)).unwrap()
        })
    });
    
    // Pre-generate signature for verification benchmark
    let signature = signer.sign_message(message, &private_key).unwrap();
    
    group.bench_function("signature_verification", |b| {
        b.iter(|| {
            signer.verify_message(
                black_box(message), 
                black_box(&signature), 
                black_box(&public_key)
            ).unwrap()
        })
    });
    
    group.finish();
}

fn bench_random_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("random_generation");
    
    let mut rng = SecureRng::new();
    let sizes = [32, 64, 256, 1024];
    
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("secure_random_bytes", size), size, |b, &size| {
            b.iter(|| rng.random_bytes(black_box(size)))
        });
    }
    
    group.bench_function("random_salt", |b| {
        b.iter(|| rng.random_salt())
    });
    
    group.bench_function("random_u64", |b| {
        b.iter(|| rng.random_u64())
    });
    
    group.finish();
}

fn bench_constant_time_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("constant_time_operations");
    
    let data_sizes = [32, 64, 256, 1024];
    
    for size in data_sizes.iter() {
        let data_a = vec![0x42u8; *size];
        let data_b = vec![0x42u8; *size];
        let data_c = vec![0x43u8; *size];
        
        group.bench_with_input(BenchmarkId::new("ct_eq_same", size), &(data_a.clone(), data_b.clone()), |b, (a, b)| {
            b.iter(|| ConstantTime::eq(black_box(a), black_box(b)))
        });
        
        group.bench_with_input(BenchmarkId::new("ct_eq_different", size), &(data_a, data_c), |b, (a, c)| {
            b.iter(|| ConstantTime::eq(black_box(a), black_box(c)))
        });
    }
    
    group.finish();
}

fn bench_crypto_utils(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_utils");
    
    group.bench_function("generate_private_key", |b| {
        b.iter(|| CryptoUtils::generate_private_key().unwrap())
    });
    
    let private_key = CryptoUtils::generate_private_key().unwrap();
    
    group.bench_function("derive_public_key", |b| {
        b.iter(|| CryptoUtils::derive_public_key(black_box(&private_key)))
    });
    
    let test_data = vec![0x42u8; 256];
    
    group.bench_function("bytes_to_hex", |b| {
        b.iter(|| CryptoUtils::bytes_to_hex(black_box(&test_data)))
    });
    
    let hex_string = CryptoUtils::bytes_to_hex(&test_data);
    
    group.bench_function("hex_to_bytes", |b| {
        b.iter(|| CryptoUtils::hex_to_bytes(black_box(&hex_string)).unwrap())
    });
    
    let private_key_bytes = private_key.secret_bytes();
    
    group.bench_function("validate_private_key", |b| {
        b.iter(|| CryptoUtils::validate_private_key(black_box(&private_key_bytes)).unwrap())
    });
    
    let public_key = CryptoUtils::derive_public_key(&private_key);
    let public_key_bytes = public_key.serialize();
    
    group.bench_function("validate_public_key", |b| {
        b.iter(|| CryptoUtils::validate_public_key(black_box(&public_key_bytes)).unwrap())
    });
    
    group.finish();
}

fn bench_memory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_operations");
    
    let sizes = [32, 256, 1024, 4096];
    
    for size in sizes.iter() {
        group.bench_with_input(BenchmarkId::new("secure_zero", size), size, |b, &size| {
            b.iter_batched(
                || vec![0x42u8; size],
                |mut data| CryptoUtils::secure_zero(black_box(&mut data)),
                criterion::BatchSize::SmallInput
            )
        });
    }
    
    group.finish();
}

fn bench_secure_string_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("secure_string_operations");
    
    let test_strings = [
        "short",
        "medium_length_string_for_testing",
        "very_long_string_that_contains_a_lot_of_characters_for_comprehensive_benchmarking_purposes",
    ];
    
    for test_str in test_strings.iter() {
        group.bench_with_input(
            BenchmarkId::new("from_string", test_str.len()), 
            test_str, 
            |b, &test_str| {
                b.iter(|| SecureString::from_string(black_box(test_str.to_string())))
            }
        );
        
        let secure_str = SecureString::from_string(test_str.to_string());
        
        group.bench_with_input(
            BenchmarkId::new("as_str", test_str.len()), 
            &secure_str, 
            |b, secure_str| {
                b.iter(|| secure_str.as_str().unwrap())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("as_bytes", test_str.len()), 
            &secure_str, 
            |b, secure_str| {
                b.iter(|| secure_str.as_bytes())
            }
        );
    }
    
    group.finish();
}

criterion_group!(
    crypto_benches,
    bench_hash_functions,
    bench_hmac_operations,
    bench_pbkdf2_operations,
    bench_secp256k1_operations,
    bench_random_generation,
    bench_constant_time_operations,
    bench_crypto_utils,
    bench_memory_operations,
    bench_secure_string_operations
);

criterion_main!(crypto_benches);