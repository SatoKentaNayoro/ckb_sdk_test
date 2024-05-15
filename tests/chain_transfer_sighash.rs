use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::str::FromStr;
use ckb_hash::blake2b_256;
use ckb_sdk::constants::SIGHASH_TYPE_HASH;
use ckb_sdk::{Address, CkbRpcClient, HumanCapacity, ScriptId, SECP256K1};
use ckb_sdk::traits::{CellCollector, DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver, DefaultTransactionDependencyProvider, SecpCkbRawKeySigner};
use ckb_sdk::tx_builder::{CapacityBalancer, TxBuilder};
use ckb_sdk::tx_builder::transfer::CapacityTransferBuilder;
use ckb_sdk::unlock::{ScriptUnlocker, SecpSighashUnlocker};
use ckb_types::bytes::Bytes;
use ckb_types::core::{BlockView, ScriptHashType, TransactionView};
use ckb_types::packed::{CellOutput, Script, WitnessArgs};
use ckb_types::prelude::{Builder, Entity, Pack};
use dotenv::dotenv;

fn build_transfer_tx(
    cell_collector: &mut DefaultCellCollector,
    tx_dep_provider: &DefaultTransactionDependencyProvider,
    ckb_rpc: &str,
    sender: Script,
    sender_key: secp256k1::SecretKey,
    receiver: Script,
    capacity: u64,
) -> Result<TransactionView, Box<dyn Error>> {
    // Build ScriptUnlocker
    let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
    let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
    let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
    let mut unlockers = HashMap::default();
    unlockers.insert(
        sighash_script_id,
        Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
    );

    // Build CapacityBalancer
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let mut balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);
    balancer.set_max_fee(Some(100_000_000));

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let ckb_client = CkbRpcClient::new(ckb_rpc);
    let cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into())?.unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block))?
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(ckb_rpc);

    // Build the transaction
    let output = CellOutput::new_builder()
        .lock(receiver)
        .capacity(capacity.pack())
        .build();
    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::default())]);
    let (tx, still_locked_groups) = builder.build_unlocked(
        cell_collector,
        &cell_dep_resolver,
        &header_dep_resolver,
        tx_dep_provider,
        &balancer,
        &unlockers,
    )?;
    assert!(still_locked_groups.is_empty());
    Ok(tx)
}

#[test]
fn test_chain_transfer_sighash() {
    dotenv().ok().unwrap();
    let capacity = HumanCapacity::from_str(env::var("Capacity").unwrap().as_str()).unwrap();


    let sender_key = secp256k1::SecretKey::from_str(env::var("SenderKey").unwrap().as_str()).unwrap();
    let sender = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1,&sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let receiver1_key = secp256k1::SecretKey::from_str(env::var("Receiver1Key").unwrap().as_str()).unwrap();
    let receiver1 =  Address::from_str(env::var("Receiver1").unwrap().as_str()).unwrap();

    let receiver1_script = Script::from(&receiver1);

    let receiver2 =  Address::from_str(env::var("Receiver2").unwrap().as_str()).unwrap();
    let receiver2_script = Script::from(&receiver2);


    let ckb_rpc = env::var("CKB_RPC").unwrap();
    let mut cell_collector = DefaultCellCollector::new(&ckb_rpc);
    let mut tx_dep_provider = DefaultTransactionDependencyProvider::new(&ckb_rpc, 10);
    let tx = build_transfer_tx(
        &mut cell_collector,
        &tx_dep_provider,
        &ckb_rpc,
        sender,
        sender_key,
        receiver1_script.clone(),
        capacity.0,
    ).unwrap();
    let ckb_client = CkbRpcClient::new(&ckb_rpc);
    let mut tip_num = ckb_client.get_tip_block_number().unwrap().value();
    cell_collector.apply_tx(tx.data(), tip_num).unwrap();
    tx_dep_provider.apply_tx(tx.data(), tip_num).unwrap();
    let tx1 = build_transfer_tx(
        &mut cell_collector,
        &tx_dep_provider,
        &ckb_rpc,
        receiver1_script,
        receiver1_key,
        receiver2_script,
        capacity.0 - 100_000,
    ).unwrap();
    tip_num = ckb_client.get_tip_block_number().unwrap().value();
    cell_collector.apply_tx(tx1.data(), tip_num).unwrap();
    tx_dep_provider.apply_tx(tx.data(), tip_num).unwrap();

    // Send transaction
    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx);
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let outputs_validator = Some(ckb_jsonrpc_types::OutputsValidator::Passthrough);
    let tx0_hash = ckb_client
        .send_transaction(json_tx.inner, outputs_validator.clone())
        .expect("send transaction");
    println!(">>> tx {} sent! <<<", tx0_hash);

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx1);
    println!("tx1: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let tx1_hash = ckb_client
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    println!(">>> tx {} sent! <<<", tx1_hash);
}