use ckb_sdk::traits::{DefaultCellCollector};

pub fn get_cell_collector(ckb_rpc: &str) -> DefaultCellCollector {
    DefaultCellCollector::new(&ckb_rpc)
}