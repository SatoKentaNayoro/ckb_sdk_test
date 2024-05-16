use std::env;
use std::str::FromStr;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_sdk::constants::SIGHASH_TYPE_HASH;
use ckb_sdk::{CkbRpcClient, NetworkInfo, SECP256K1};
use ckb_sdk::traits::{CellCollector, CellQueryOptions, LiveCell, ValueRangeOption};
use ckb_types::bytes::Bytes;
use ckb_types::core::{Capacity, DepType, FeeRate, ScriptHashType, TransactionBuilder};
use ckb_types::h256;
use ckb_types::packed::{Bytes as PackBytes, CellbaseWitnessBuilder, CellDep, CellInput, CellOutput, OutPoint, Script, Uint64};
use ckb_types::prelude::{Builder, Entity, Pack, Unpack};
use dotenv::dotenv;
use ckb_test::get_cell_collector;


struct RgbppTokenInfo {
    decimal: u8,
    name: String,
    // max 255
    symbol: String, // max 255
}

impl RgbppTokenInfo {
    fn encode_rgbpp_token_info(&self) -> Bytes {
        let name_hex = hex::encode(&self.name);
        let name = name_hex.as_bytes();
        let symbol_hex = hex::encode(&self.symbol);
        let symbol = symbol_hex.as_bytes();

        let mut bytes_vec = vec![];
        bytes_vec.push(self.decimal);
        bytes_vec.extend_from_slice(&(name.len() as u32).to_le_bytes());
        bytes_vec.extend_from_slice(name);
        bytes_vec.extend_from_slice(&(symbol.len() as u32).to_le_bytes());
        bytes_vec.extend_from_slice(symbol);
        Bytes::from(bytes_vec)
    }
}

#[test]
fn test_xudt() {
    dotenv().ok().unwrap();
    let network_info = NetworkInfo::testnet();

    let xudt = RgbppTokenInfo {
        decimal: 8,
        name: "Test CKB Bool Token".to_string(),
        symbol: "TCBT".to_string(),
    };

    let mut cell_collector = get_cell_collector(&network_info.url);

    let sender_key = secp256k1::SecretKey::from_str(env::var("SenderKey").unwrap().as_str()).unwrap();
    let sender = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let query = {
        let mut query = CellQueryOptions::new_lock(sender.clone());
        query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        // query.min_total_capacity = output0_capacity + output1_capacity + 2000_0000;
        query
    };
    let mut empty_cells = cell_collector.collect_live_cells(&query, false).unwrap().0;
    println!("empty_cells_before_check: {:?}", empty_cells);
    empty_cells.retain(|cell|cell.output.type_().is_none());
    println!("empty_cells: {:?}", empty_cells);
    assert!(!empty_cells.is_empty());

    let sender_lock_capacity = sender.occupied_capacity().unwrap().as_u64();
    println!("xudt_capacity {sender_lock_capacity}");
    let xudt_info_capacity = Capacity::bytes(xudt.encode_rgbpp_token_info().len()).unwrap().as_u64();
    println!("xudt_info_capacity {xudt_info_capacity}");
    let xudt_type = Script::new_builder()
        .code_hash(h256!("0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb").pack())
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(sender.calc_script_hash().as_bytes()).pack())
        .build();

    let xudt_type_capacity = xudt_type.occupied_capacity().unwrap().as_u64();
    println!("xudt_type_capacity {xudt_info_capacity}");

    // println!("xUDT type script: {}", xudt_type);

    let unique_type_script = Script::new_builder()
        .code_hash(h256!("0x8e341bcfec6393dcd41e635733ff2dca00a6af546949f70c57a706c0f344df8b").pack())
        .hash_type(ScriptHashType::Type.into())
        .args(generate_unique_type_args(CellInput::new_builder().previous_output(empty_cells[0].clone().out_point).build(), 1))
        .build();

    let unique_type_capacity = unique_type_script.occupied_capacity().unwrap().as_u64();
    println!("unique_type_capacity {xudt_info_capacity}");

    let total_amount = 2100_0000 * (10u128.pow(xudt.decimal as u32));
    let output_datas = vec![
        Bytes::from(total_amount.to_le_bytes().to_vec()),
        xudt.encode_rgbpp_token_info(),
        Bytes::default()
    ];

    let output0_capacity = sender_lock_capacity + xudt_type_capacity + Capacity::bytes(8).unwrap().as_u64() + Capacity::bytes(output_datas[0].len()).unwrap().as_u64();
    let output1_capacity = sender_lock_capacity + unique_type_capacity + xudt_info_capacity + Capacity::bytes(8).unwrap().as_u64() + Capacity::bytes(output_datas[1].len()).unwrap().as_u64();
    println!("out0 capacity {}", output0_capacity);
    println!("out1 capacity {}", output1_capacity);

    let (inputs, sum_inputs_capacity) = collect_inputs(
        empty_cells,
        output0_capacity + output1_capacity,
        2000_0000,
    );

    let change_capacity = sum_inputs_capacity - output0_capacity - output1_capacity;

    let mut outputs = vec![
        CellOutput::new_builder()
            .lock(sender.clone())
            .type_(Some(xudt_type).pack())
            .capacity(output0_capacity.pack())
            .build(),
        CellOutput::new_builder()
            .lock(sender.clone())
            .type_(Some(unique_type_script).pack())
            .capacity(output1_capacity.pack())
            .build(),
        CellOutput::new_builder()
            .lock(sender.clone())
            .capacity(change_capacity.pack())
            .build()
    ];

    let base_witness = CellbaseWitnessBuilder::default().build();

    let witnesses = inputs.iter().enumerate().map(|(index, _)| {
        if index == 0 {
            base_witness.as_bytes()
        } else {
            Bytes::from("0x")
        }
    }).collect::<Vec<_>>();

    let secp256k1cell_dep = CellDep::new_builder()
        .out_point(OutPoint::new_builder()
            .tx_hash(
                h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
                    .pack(),
            )
            .index(0u32.pack())
            .build()
        )
        .dep_type(DepType::DepGroup.into())
        .build();

    let unique_type_dep = CellDep::new_builder()
        .out_point(OutPoint::new_builder()
            .tx_hash(
                h256!("0xff91b063c78ed06f10a1ed436122bd7d671f9a72ef5f5fa28d05252c17cf4cef")
                    .pack(),
            )
            .index(0u32.pack())
            .build()
        ).build();

    let xudttype_dep = CellDep::new_builder()
        .out_point(OutPoint::new_builder()
            .tx_hash(
                h256!("0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f")
                    .pack(),
            )
            .index(0u32.pack())
            .build()
        ).build();


    let tx_before = TransactionBuilder::default()
        .inputs(inputs.clone())
        .outputs(outputs.clone())
        .outputs_data(output_datas.pack())
        .cell_dep(secp256k1cell_dep.clone())
        .cell_dep(unique_type_dep.clone())
        .cell_dep(xudttype_dep.clone())
        .witnesses(witnesses.pack())
        .build();

    let ckb_client = CkbRpcClient::new(&network_info.url);

    let f = ckb_client.get_fee_rate_statics(None).unwrap().unwrap();

    let tx_size = tx_before.pack().as_bytes().len() + 65;
    let tx_capacity = tx_size as u64 * f.mean.value();
    println!("tx_capacity {tx_capacity}");

    let change_capacity = change_capacity - tx_capacity;

    println!("change_capacity {change_capacity}");

    let _ = outputs.pop();
    outputs.push(
        CellOutput::new_builder()
            .lock(sender.clone())
            .capacity(change_capacity.pack())
            .build()
    );

    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(output_datas.pack())
        .cell_dep(secp256k1cell_dep)
        .cell_dep(unique_type_dep)
        .cell_dep(xudttype_dep)
        .witnesses(witnesses.pack())
        .build();

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx);
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let outputs_validator = Some(ckb_jsonrpc_types::OutputsValidator::Passthrough);

    let tx_hash = ckb_client
        .send_transaction(json_tx.inner, outputs_validator.clone())
        .expect("send transaction");
    println!(">>> tx {} sent! <<<", tx_hash);
}

fn collect_inputs(
    live_cells: Vec<LiveCell>,
    need_capacity: u64,
    fee: u64,
) -> (Vec<CellInput>, u64) {
    let rgbpp_lock_script = Script::new_builder()
        .code_hash(h256!("0x61ca7a4796a4eb19ca4f0d065cb9b10ddcf002f10f7cbb810c706cb6bb5c3248").pack())
        .hash_type(ScriptHashType::Type.into())
        .build();

    let change_capacity = 61 * 10000_0000u64;
    let mut inputs = vec![];
    let mut sum_inputs_capacity = 0u64;

    let is_rgbpp_lock = !live_cells.is_empty()
        && live_cells[0].output.lock().code_hash().eq(&rgbpp_lock_script.code_hash())
        && live_cells[0].output.lock().hash_type().eq(&rgbpp_lock_script.hash_type());

    for cell in live_cells {
        inputs.push(
            CellInput::new_builder()
                .previous_output(cell.out_point)
                .build()
        );
        sum_inputs_capacity += <Uint64 as Unpack<u64>>::unpack(&cell.output.capacity());
        if sum_inputs_capacity >= need_capacity.clone() + change_capacity + fee && !is_rgbpp_lock {
            break;
        }
    }

    if sum_inputs_capacity < need_capacity + change_capacity + fee {
        panic!("Insufficient free CKB balance");
    }

    (inputs, sum_inputs_capacity)
}

fn generate_unique_type_args(first_input: CellInput, first_output_index: u64) -> PackBytes {
    let input = first_input.as_bytes();
    let mut hasher = new_blake2b();
    hasher.update(input.as_ref());
    hasher.update(first_output_index.to_le_bytes().as_ref());
    let mut args =  [0u8; 40];
    hasher.finalize(&mut args);
    args.pack()
}