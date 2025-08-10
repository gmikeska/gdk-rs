//! Performance benchmarks for BIP39 mnemonic operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gdk_rs::bip39::*;

fn bench_mnemonic_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_generation");
    
    let entropy_sizes = [128, 160, 192, 224, 256]; // bits
    
    for entropy_bits in entropy_sizes.iter() {
        group.bench_with_input(
            BenchmarkId::new("generate", entropy_bits), 
            entropy_bits, 
            |b, &entropy_bits| {
                b.iter(|| Mnemonic::generate(black_box(entropy_bits)).unwrap())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("generate_with_language", entropy_bits), 
            entropy_bits, 
            |b, &entropy_bits| {
                b.iter(|| Mnemonic::generate_with_language(black_box(entropy_bits), Language::English).unwrap())
            }
        );
    }
    
    group.finish();
}

fn bench_mnemonic_from_entropy(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_from_entropy");
    
    let entropy_sizes = [16, 20, 24, 28, 32]; // bytes
    
    for entropy_bytes in entropy_sizes.iter() {
        let entropy = vec![0x42u8; *entropy_bytes];
        
        group.bench_with_input(
            BenchmarkId::new("from_entropy", entropy_bytes), 
            &entropy, 
            |b, entropy| {
                b.iter(|| Mnemonic::from_entropy(black_box(entropy)).unwrap())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("from_entropy_with_language", entropy_bytes), 
            &entropy, 
            |b, entropy| {
                b.iter(|| Mnemonic::from_entropy_with_language(black_box(entropy), Language::English).unwrap())
            }
        );
    }
    
    group.finish();
}

fn bench_mnemonic_from_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_from_string");
    
    let test_mnemonics = [
        ("12_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        ("15_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address"),
        ("18_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"),
        ("21_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon able"),
        ("24_words", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
    ];
    
    for (name, mnemonic_str) in test_mnemonics.iter() {
        group.bench_with_input(
            BenchmarkId::new("from_str", name), 
            mnemonic_str, 
            |b, &mnemonic_str| {
                b.iter(|| Mnemonic::from_str(black_box(mnemonic_str)).unwrap())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("from_str_with_language", name), 
            mnemonic_str, 
            |b, &mnemonic_str| {
                b.iter(|| Mnemonic::from_str_with_language(black_box(mnemonic_str), Language::English).unwrap())
            }
        );
    }
    
    group.finish();
}

fn bench_mnemonic_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_validation");
    
    let test_mnemonics = [
        ("12_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap()),
        ("15_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address").unwrap()),
        ("18_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent").unwrap()),
        ("21_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon able").unwrap()),
        ("24_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art").unwrap()),
    ];
    
    for (name, mnemonic) in test_mnemonics.iter() {
        group.bench_with_input(
            BenchmarkId::new("validate", name), 
            mnemonic, 
            |b, mnemonic| {
                b.iter(|| mnemonic.validate().unwrap())
            }
        );
    }
    
    group.finish();
}

fn bench_mnemonic_to_seed(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_to_seed");
    
    let test_mnemonics = [
        ("12_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap()),
        ("15_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address").unwrap()),
        ("18_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent").unwrap()),
        ("21_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon able").unwrap()),
        ("24_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art").unwrap()),
    ];
    
    for (name, mnemonic) in test_mnemonics.iter() {
        group.bench_with_input(
            BenchmarkId::new("to_seed_no_passphrase", name), 
            mnemonic, 
            |b, mnemonic| {
                b.iter(|| mnemonic.to_seed(black_box(None)).unwrap())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("to_seed_with_passphrase", name), 
            mnemonic, 
            |b, mnemonic| {
                b.iter(|| mnemonic.to_seed(black_box(Some("test_passphrase"))).unwrap())
            }
        );
    }
    
    group.finish();
}

fn bench_mnemonic_to_entropy(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_to_entropy");
    
    let test_mnemonics = [
        ("12_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap()),
        ("15_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address").unwrap()),
        ("18_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent").unwrap()),
        ("21_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon able").unwrap()),
        ("24_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art").unwrap()),
    ];
    
    for (name, mnemonic) in test_mnemonics.iter() {
        group.bench_with_input(
            BenchmarkId::new("to_entropy", name), 
            mnemonic, 
            |b, mnemonic| {
                b.iter(|| mnemonic.to_entropy().unwrap())
            }
        );
    }
    
    group.finish();
}

fn bench_mnemonic_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_roundtrip");
    
    let entropy_sizes = [16, 20, 24, 28, 32]; // bytes
    
    for entropy_bytes in entropy_sizes.iter() {
        let entropy = vec![0x42u8; *entropy_bytes];
        
        group.bench_with_input(
            BenchmarkId::new("entropy_to_mnemonic_to_entropy", entropy_bytes), 
            &entropy, 
            |b, entropy| {
                b.iter(|| {
                    let mnemonic = Mnemonic::from_entropy(black_box(entropy)).unwrap();
                    mnemonic.to_entropy().unwrap()
                })
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("entropy_to_mnemonic_to_seed", entropy_bytes), 
            &entropy, 
            |b, entropy| {
                b.iter(|| {
                    let mnemonic = Mnemonic::from_entropy(black_box(entropy)).unwrap();
                    mnemonic.to_seed(None).unwrap()
                })
            }
        );
    }
    
    group.finish();
}

fn bench_language_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("language_operations");
    
    let language = Language::English;
    
    group.bench_function("wordlist_access", |b| {
        b.iter(|| language.wordlist())
    });
    
    let wordlist = language.wordlist();
    
    group.bench_function("wordlist_search", |b| {
        b.iter(|| {
            wordlist.iter().position(|&word| word == black_box("abandon"))
        })
    });
    
    group.bench_function("wordlist_random_access", |b| {
        b.iter(|| {
            let index = black_box(1000);
            wordlist[index]
        })
    });
    
    group.finish();
}

fn bench_seed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("seed_operations");
    
    let seed_bytes = [0x42u8; 64];
    let seed = Seed(seed_bytes);
    
    group.bench_function("seed_as_bytes", |b| {
        b.iter(|| seed.as_bytes())
    });
    
    group.bench_function("seed_to_vec", |b| {
        b.iter(|| seed.to_vec())
    });
    
    group.bench_function("seed_clone", |b| {
        b.iter(|| seed.clone())
    });
    
    group.finish();
}

fn bench_mnemonic_string_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_string_operations");
    
    let test_mnemonics = [
        ("12_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap()),
        ("24_words", Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art").unwrap()),
    ];
    
    for (name, mnemonic) in test_mnemonics.iter() {
        group.bench_with_input(
            BenchmarkId::new("to_string", name), 
            mnemonic, 
            |b, mnemonic| {
                b.iter(|| mnemonic.to_string())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("words", name), 
            mnemonic, 
            |b, mnemonic| {
                b.iter(|| mnemonic.words())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("language", name), 
            mnemonic, 
            |b, mnemonic| {
                b.iter(|| mnemonic.language())
            }
        );
    }
    
    group.finish();
}

fn bench_mnemonic_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("mnemonic_memory_usage");
    
    let word_counts = [12, 15, 18, 21, 24];
    
    for word_count in word_counts.iter() {
        let entropy_bytes = (word_count * 11 * 32) / (33 * 8); // Calculate entropy bytes
        
        group.bench_with_input(
            BenchmarkId::new("create_and_drop", word_count), 
            &entropy_bytes, 
            |b, &entropy_bytes| {
                b.iter_batched(
                    || vec![0x42u8; entropy_bytes],
                    |entropy| {
                        let mnemonic = Mnemonic::from_entropy(black_box(&entropy)).unwrap();
                        black_box(mnemonic)
                    },
                    criterion::BatchSize::SmallInput
                )
            }
        );
    }
    
    group.finish();
}

criterion_group!(
    bip39_benches,
    bench_mnemonic_generation,
    bench_mnemonic_from_entropy,
    bench_mnemonic_from_string,
    bench_mnemonic_validation,
    bench_mnemonic_to_seed,
    bench_mnemonic_to_entropy,
    bench_mnemonic_roundtrip,
    bench_language_operations,
    bench_seed_operations,
    bench_mnemonic_string_operations,
    bench_mnemonic_memory_usage
);

criterion_main!(bip39_benches);