use std::env;
use std::str::FromStr;
use ckb_hash::{blake2b_256, new_blake2b};
use ckb_sdk::constants::SIGHASH_TYPE_HASH;
use ckb_sdk::{CkbRpcClient, NetworkInfo, SECP256K1};
use ckb_sdk::traits::{CellCollector, CellQueryOptions, LiveCell, ValueRangeOption};
use ckb_sdk::transaction::builder::CkbTransactionBuilder;
use ckb_sdk::transaction::input::TransactionInput;
use ckb_sdk::transaction::signer::{SignContexts, TransactionSigner};
use ckb_sdk::transaction::TransactionBuilderConfiguration;
use ckb_types::bytes::Bytes;
use ckb_types::core::{Capacity, DepType, ScriptHashType};
use ckb_types::{h256, H256};
use ckb_types::packed::{Bytes as PackBytes, CellDep, CellInput, CellOutput, OutPoint, Script, Uint64};
use ckb_types::prelude::{Builder, Entity, Pack, Unpack};
use dotenv::dotenv;
use xudt_manager::XudtTransactionBuilder;
use ckb_test::get_cell_collector;


#[derive(Clone)]
struct RgbppTokenInfo {
    decimal: u8,
    name: String,
    // max 255
    symbol: String, // max 255
}

impl RgbppTokenInfo {
    fn encode_rgbpp_token_info(&self) -> String {
        let decimal = hex::encode(&vec![self.decimal]);
        println!("decimal {}", decimal);
        let name_hex = hex::encode(&self.name);
        println!("name_hex {}", name_hex);
        let name_size =  hex::encode(&vec![(name_hex.len()/2) as u8]);
        println!("name_size {}", name_size);
        let symbol_hex = hex::encode(&self.symbol);
        println!("symbol_hex {}", symbol_hex);
        let symbol_size = hex::encode(&vec![(symbol_hex.len()/2) as u8]);
        println!("symbol_size {}", symbol_size);
        let hex = format!("{}{}{}{}{}", decimal,name_size, name_hex,symbol_size, symbol_hex);
        println!("hex {}", hex);
        println!("hex len {}", hex.len());

        hex
    }
}

#[test]
fn test_xudt() {
    dotenv().ok().unwrap();
    let network_info = NetworkInfo::testnet();

    let xudt = RgbppTokenInfo {
        decimal: 8,
        name: "XUDT Test B Token".to_string(),
        symbol: "XTTB".to_string(),
    };

    let client = CkbRpcClient::new(network_info.url.as_str());

    let mut cell_collector = get_cell_collector(&network_info.url);

    let sender_private_key = H256::from_str( env::var("SenderKey").unwrap().as_str()).unwrap();
    let sender = {
        let sender_key = secp256k1::SecretKey::from_slice(sender_private_key.as_bytes())
            .map_err(|err| format!("invalid sender secret key: {}", err)).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let ckb_query = {
        let mut query = CellQueryOptions::new_lock(sender.clone());
        query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        // query.min_total_capacity = output0_capacity + output1_capacity + 2000_0000;
        query
    };
    let mut ckb_cells = cell_collector.collect_live_cells(&ckb_query, false).unwrap().0;
    assert!(!ckb_cells.is_empty());
    ckb_cells.retain(|cell|cell.output.type_().is_none());
    println!("empty_cells: {:?}", ckb_cells);

    let sender_lock_capacity = calculate_udt_cell_capacity(sender.clone()) as u64 * 10000_0000;
    println!("xudt_capacity {sender_lock_capacity}");
    let xudt_info_capacity = calculate_xudt_token_info_cell_capacity(xudt.clone(),sender.clone()) as u64 * 10000_00000;
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
        .args(generate_unique_type_args(CellInput::new_builder().previous_output(ckb_cells[0].clone().out_point).build(), 1))
        .build();

    let unique_type_capacity = unique_type_script.occupied_capacity().unwrap().as_u64();
    println!("unique_type_capacity {xudt_info_capacity}");

    // println!("{}", xudt.encode_rgbpp_token_info().len());
    // println!("{}", xudt.encode().as_bytes().len());

    let total_amount = 2100_0000 * (10u128.pow(xudt.decimal as u32));
    let output_datas = vec![
        Bytes::from(total_amount.to_le_bytes().to_vec()),
        xudt.encode_rgbpp_token_info().into(),
        Bytes::default()
    ];

    let secp256k1_dep = CellDep::new_builder()
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

    let xudt_type_dep = CellDep::new_builder()
        .out_point(OutPoint::new_builder()
            .tx_hash(
                h256!("0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f")
                    .pack(),
            )
            .index(0u32.pack())
            .build()
        ).build();

    let configuration = TransactionBuilderConfiguration::new_with_network(network_info.clone()).unwrap();

    let mut builder = XudtTransactionBuilder::new(
        sender.clone(),
        sender.clone(),
        configuration,
        vec![],
    );

    builder.add_input(
        TransactionInput{
            live_cell: ckb_cells[0].clone(),
            since: 0
        },
        0
    );

    builder.add_output_and_data(
        CellOutput::new_builder()
                .lock(sender.clone())
                .type_(Some(xudt_type).pack())
                .capacity(sender_lock_capacity.pack())
                .build(),
        output_datas[0].pack()
    );

    builder.add_output_and_data(
        CellOutput::new_builder()
            .lock(sender.clone())
            .type_(Some(unique_type_script).pack())
            .capacity(xudt_info_capacity.pack())
            .build(),
        output_datas[1].pack()
    );

    builder.add_output_and_data(
        CellOutput::new_builder()
            .lock(sender.clone())
            .build(),
        PackBytes::default()
    );
    builder.add_cell_dep(secp256k1_dep);
    builder.add_cell_dep(unique_type_dep);
    builder.add_cell_dep(xudt_type_dep);


    let mut tx_with_groups = builder.build(&Default::default()).unwrap();
    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());
    let private_keys = vec![sender_private_key];
    TransactionSigner::new(&network_info).sign_transaction(
        &mut tx_with_groups,
        &SignContexts::new_sighash_h256(private_keys).unwrap(),
    ).unwrap();

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let tx_hash = client
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");

    println!(">>> tx {} sent! <<<", tx_hash);
}

#[allow(dead_code)]
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
    println!("input {:?}", input.as_ref());
    let mut hasher = new_blake2b();
    hasher.update(input.as_ref());
    hasher.update(first_output_index.to_le_bytes().as_ref());
    println!("first_output_index {:?}", first_output_index.to_le_bytes().as_ref());
    let mut args =  [0u8; 40];
    hasher.finalize(&mut args);
    println!("args {:?}", &args[0..20]);
    args[0..20].pack()
}

fn calculate_udt_cell_capacity(lock: Script) -> usize {
    let args_size = lock.args().len();
    let type_args = 32;
    let cell_size = 33 + args_size + 33 + type_args + 8 + 16;
    cell_size + 1
}

fn calculate_xudt_token_info_cell_capacity(token_info: RgbppTokenInfo, lock:  Script) -> usize {
    let lock_size = lock.args().len() + 33;
    println!("lock_size {}", lock_size);
    let cell_data_size = token_info.encode_rgbpp_token_info().len()/2;
    println!("cell_data_size {}", cell_data_size);
    let unique_type_size = 32 + 1 + 20;
    lock_size + unique_type_size + 8 + cell_data_size
}