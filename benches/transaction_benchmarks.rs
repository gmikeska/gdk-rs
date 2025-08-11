//! Performance benchmarks for transaction operations

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use gdk_rs::primitives::transaction::*;
use gdk_rs::primitives::script::Script;
use gdk_rs::primitives::encode::{Encodable, Decodable};
use gdk_rs::transaction_builder::*;
use gdk_rs::primitives::address::Network;
use std::io::Cursor;

fn create_test_transaction(input_count: usize, output_count: usize, has_witness: bool) -> Transaction {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    
    for i in 0..input_count {
        let mut txid = [0u8; 32];
        txid[0] = i as u8;
        
        let input = TxIn {
            previous_output: OutPoint::new(txid, i as u32),
            script_sig: if has_witness { 
                Script::new() 
            } else { 
                Script::from_bytes(vec![0x76, 0xa9, 0x14]) // P2PKH script_sig placeholder
            },
            sequence: 0xffffffff,
            witness: if has_witness {
                vec![
                    vec![0x30, 0x44, 0x02, 0x20], // Dummy signature
                    vec![0x03, 0x21], // Dummy pubkey
                ]
            } else {
                Vec::new()
            },
        };
        inputs.push(input);
    }
    
    for i in 0..output_count {
        let output = TxOut {
            value: 100000 + (i as u64 * 10000),
            script_pubkey: Script::new_p2pkh(&[(i as u8); 20]),
        };
        outputs.push(output);
    }
    
    Transaction {
        version: if has_witness { 2 } else { 1 },
        lock_time: 0,
        input: inputs,
        output: outputs,
    }
}

fn bench_transaction_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_creation");
    
    let configurations = [
        (1, 1, false),   // Simple legacy transaction
        (1, 2, false),   // Legacy with change
        (2, 1, false),   // Multi-input legacy
        (1, 1, true),    // Simple witness transaction
        (1, 2, true),    // Witness with change
        (2, 1, true),    // Multi-input witness
        (10, 5, false), // Large legacy transaction
        (10, 5, true),  // Large witness transaction
    ];
    
    for (inputs, outputs, witness) in configurations.iter() {
        let name = format!("{}i_{}o_{}", inputs, outputs, if *witness { "witness" } else { "legacy" });
        
        group.bench_with_input(
            BenchmarkId::new("create_transaction", &name),
            &(*inputs, *outputs, *witness),
            |b, &(inputs, outputs, witness)| {
                b.iter(|| create_test_transaction(black_box(inputs), black_box(outputs), black_box(witness)))
            }
        );
    }
    
    group.finish();
}

fn bench_transaction_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_serialization");
    
    let test_transactions = [
        ("simple_legacy", create_test_transaction(1, 1, false)),
        ("simple_witness", create_test_transaction(1, 1, true)),
        ("multi_input_legacy", create_test_transaction(5, 2, false)),
        ("multi_input_witness", create_test_transaction(5, 2, true)),
        ("large_legacy", create_test_transaction(20, 10, false)),
        ("large_witness", create_test_transaction(20, 10, true)),
    ];
    
    for (name, tx) in test_transactions.iter() {
        group.bench_with_input(
            BenchmarkId::new("encode", name),
            tx,
            |b, tx| {
                b.iter(|| {
                    let mut encoded = Vec::new();
                    tx.consensus_encode(black_box(&mut encoded)).unwrap();
                    encoded
                })
            }
        );
        
        // Pre-encode for decode benchmark
        let mut encoded = Vec::new();
        tx.consensus_encode(&mut encoded).unwrap();
        
        group.bench_with_input(
            BenchmarkId::new("decode", name),
            &encoded,
            |b, encoded| {
                b.iter(|| {
                    let mut cursor = Cursor::new(black_box(encoded));
                    Transaction::consensus_decode(&mut cursor).unwrap()
                })
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("encode_decode_roundtrip", name),
            tx,
            |b, tx| {
                b.iter(|| {
                    let mut encoded = Vec::new();
                    tx.consensus_encode(&mut encoded).unwrap();
                    let mut cursor = Cursor::new(&encoded);
                    Transaction::consensus_decode(black_box(&mut cursor)).unwrap()
                })
            }
        );
    }
    
    group.finish();
}

fn bench_transaction_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_hashing");
    
    let test_transactions = [
        ("simple_legacy", create_test_transaction(1, 1, false)),
        ("simple_witness", create_test_transaction(1, 1, true)),
        ("multi_input_legacy", create_test_transaction(5, 2, false)),
        ("multi_input_witness", create_test_transaction(5, 2, true)),
        ("large_legacy", create_test_transaction(20, 10, false)),
        ("large_witness", create_test_transaction(20, 10, true)),
    ];
    
    for (name, tx) in test_transactions.iter() {
        group.bench_with_input(
            BenchmarkId::new("txid", name),
            tx,
            |b, tx| {
                b.iter(|| tx.txid())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("wtxid", name),
            tx,
            |b, tx| {
                b.iter(|| tx.wtxid())
            }
        );
        
        if tx.has_witness() {
            group.bench_with_input(
                BenchmarkId::new("witness_hash", name),
                tx,
                |b, tx| {
                    b.iter(|| tx.witness_hash())
                }
            );
        }
    }
    
    group.finish();
}

fn bench_transaction_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_validation");
    
    let test_transactions = [
        ("simple_legacy", create_test_transaction(1, 1, false)),
        ("simple_witness", create_test_transaction(1, 1, true)),
        ("multi_input", create_test_transaction(5, 2, true)),
        ("large_transaction", create_test_transaction(20, 10, true)),
    ];
    
    for (name, tx) in test_transactions.iter() {
        group.bench_with_input(
            BenchmarkId::new("has_witness", name),
            tx,
            |b, tx| {
                b.iter(|| tx.has_witness())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("is_rbf_signaling", name),
            tx,
            |b, tx| {
                b.iter(|| tx.is_rbf_signaling())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("is_coinbase", name),
            tx,
            |b, tx| {
                b.iter(|| tx.is_coinbase())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("total_size", name),
            tx,
            |b, tx| {
                b.iter(|| tx.total_size())
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("base_size", name),
            tx,
            |b, tx| {
                b.iter(|| tx.base_size())
            }
        );
        
        if tx.has_witness() {
            group.bench_with_input(
                BenchmarkId::new("witness_size", name),
                tx,
                |b, tx| {
                    b.iter(|| tx.witness_size())
                }
            );
            
            group.bench_with_input(
                BenchmarkId::new("vsize", name),
                tx,
                |b, tx| {
                    b.iter(|| tx.vsize())
                }
            );
        }
    }
    
    group.finish();
}

fn bench_transaction_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_builder");
    
    group.bench_function("new_builder", |b| {
        b.iter(|| TransactionBuilder::new(black_box(Network::Testnet)))
    });
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add some UTXOs for testing
    for i in 0..5 {
        let mut txid = [0u8; 32];
        txid[0] = i;
        let outpoint = OutPoint::new(txid, i as u32);
        let utxo = TxOut {
            value: 100000,
            script_pubkey: Script::new_p2pkh(&[i; 20]),
        };
        builder.add_utxo(outpoint, utxo);
    }
    
    group.bench_function("add_utxo", |b| {
        b.iter_batched(
            || {
                let mut builder = TransactionBuilder::new(Network::Testnet);
                let outpoint = OutPoint::new([1; 32], 0);
                let utxo = TxOut {
                    value: 100000,
                    script_pubkey: Script::new_p2pkh(&[0; 20]),
                };
                (builder, outpoint, utxo)
            },
            |(mut builder, outpoint, utxo)| {
                builder.add_utxo(black_box(outpoint), black_box(utxo))
            },
            criterion::BatchSize::SmallInput
        )
    });
    
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 50000,
        asset_id: None,
    };
    
    group.bench_function("add_addressee", |b| {
        b.iter_batched(
            || {
                let mut builder = TransactionBuilder::new(Network::Testnet);
                // Add a UTXO first
                let outpoint = OutPoint::new([1; 32], 0);
                let utxo = TxOut {
                    value: 100000,
                    script_pubkey: Script::new_p2pkh(&[0; 20]),
                };
                builder.add_utxo(outpoint, utxo);
                builder
            },
            |mut builder| {
                builder.add_addressee(black_box(addressee.clone())).unwrap()
            },
            criterion::BatchSize::SmallInput
        )
    });
    
    group.bench_function("set_fee_rate", |b| {
        b.iter_batched(
            || TransactionBuilder::new(Network::Testnet),
            |mut builder| {
                builder.set_fee_rate(black_box(1000))
            },
            criterion::BatchSize::SmallInput
        )
    });
    
    group.finish();
}

fn bench_outpoint_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("outpoint_operations");
    
    let txid = [0x42u8; 32];
    let vout = 1;
    
    group.bench_function("new", |b| {
        b.iter(|| OutPoint::new(black_box(txid), black_box(vout)))
    });
    
    let outpoint = OutPoint::new(txid, vout);
    
    group.bench_function("is_null", |b| {
        b.iter(|| outpoint.is_null())
    });
    
    group.bench_function("null", |b| {
        b.iter(|| OutPoint::null())
    });
    
    let null_outpoint = OutPoint::null();
    
    group.bench_function("is_null_on_null", |b| {
        b.iter(|| null_outpoint.is_null())
    });
    
    group.finish();
}

fn bench_script_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("script_operations");
    
    let script_data = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 <20 bytes>
    
    group.bench_function("new", |b| {
        b.iter(|| Script::new())
    });
    
    group.bench_function("from_bytes", |b| {
        b.iter(|| Script::from_bytes(black_box(script_data.clone())))
    });
    
    let script = Script::from_bytes(script_data);
    
    group.bench_function("is_empty", |b| {
        b.iter(|| script.is_empty())
    });
    
    group.bench_function("len", |b| {
        b.iter(|| script.len())
    });
    
    group.bench_function("as_bytes", |b| {
        b.iter(|| script.as_bytes())
    });
    
    // Test different script types
    let p2pkh_script = Script::new_p2pkh(&[0; 20]);
    let p2sh_script = Script::new_p2sh(&[0; 20]);
    let p2wpkh_script = Script::new_p2wpkh(&[0; 20]);
    let p2wsh_script = Script::new_p2wsh(&[0; 32]);
    
    group.bench_function("new_p2pkh", |b| {
        b.iter(|| Script::new_p2pkh(black_box(&[0; 20])))
    });
    
    group.bench_function("new_p2sh", |b| {
        b.iter(|| Script::new_p2sh(black_box(&[0; 20])))
    });
    
    group.bench_function("new_p2wpkh", |b| {
        b.iter(|| Script::new_p2wpkh(black_box(&[0; 20])))
    });
    
    group.bench_function("new_p2wsh", |b| {
        b.iter(|| Script::new_p2wsh(black_box(&[0; 32])))
    });
    
    group.bench_function("is_p2pkh", |b| {
        b.iter(|| p2pkh_script.is_p2pkh())
    });
    
    group.bench_function("is_p2sh", |b| {
        b.iter(|| p2sh_script.is_p2sh())
    });
    
    group.bench_function("is_p2wpkh", |b| {
        b.iter(|| p2wpkh_script.is_p2wpkh())
    });
    
    group.bench_function("is_p2wsh", |b| {
        b.iter(|| p2wsh_script.is_p2wsh())
    });
    
    group.finish();
}

fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    
    let transaction_sizes = [1, 5, 10, 50, 100];
    
    for size in transaction_sizes.iter() {
        group.bench_with_input(
            BenchmarkId::new("create_large_transaction", size),
            size,
            |b, &size| {
                b.iter_batched(
                    || size,
                    |size| {
                        black_box(create_test_transaction(size, size, true))
                    },
                    criterion::BatchSize::SmallInput
                )
            }
        );
    }
    
    group.finish();
}

criterion_group!(
    transaction_benches,
    bench_transaction_creation,
    bench_transaction_serialization,
    bench_transaction_hashing,
    bench_transaction_validation,
    bench_transaction_builder,
    bench_outpoint_operations,
    bench_script_operations,
    bench_memory_usage
);

criterion_main!(transaction_benches);