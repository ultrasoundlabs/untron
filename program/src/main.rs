#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::{sol, SolType};
use hex_literal::hex;
use sha2::{Digest, Sha256};

fn hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn combine_hashes(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut combined = Vec::new();
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    hash(&combined)
}

fn create_merkle_tree(leaves: &[Vec<u8>]) -> Vec<u8> {
    if leaves.is_empty() {
        return Vec::new();
    }

    let mut current_level = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(combine_hashes(&chunk[0], &chunk[1]));
            } else {
                next_level.push(chunk[0].clone());
            }
        }

        current_level = next_level;
    }

    current_level[0].clone()
}

struct UsdtTransfer {
    to: [u8; 20],
    value: u64,
}

fn read_varint(arr: &[u8]) -> (usize, usize) {
    let mut shift = 0usize;
    let mut result = 0;
    let mut offset = 0;
    loop {
        let i = arr[offset];
        result |= ((i & 0x7f) as usize) << shift;
        shift += 7;
        if i & 0x80 == 0 {
            break;
        }
        offset += 1;
    }

    (result, offset + 1)
}

// assert_eq but None instead of panic
fn wagmi<T: core::cmp::PartialEq>(left: T, right: T) -> Option<()> {
    if left == right {
        Some(())
    } else {
        None
    }
}

fn parse_usdt_transfer(tx: &[u8]) -> Option<UsdtTransfer> {
    wagmi(tx[tx.len() - 1], 1)?; // ret.contractRet: SUCCESS (THIS THING IS CRITICAL!!!)

    wagmi(tx[0] & 7, 2)?; // LEN
    wagmi(tx[0] >> 3, 1)?; // 1:
    let (_, mut offset) = read_varint(tx);
    offset += 1;

    // skipping unnecessary protobuf elements
    loop {
        if offset >= tx.len() {
            return None;
        }
        let t = tx[offset];
        if t == 0x5a {
            // 11: LEN
            break;
        }
        offset += 1;
        if t & 7 == 5 {
            offset += 4;
        } else {
            let (length, v) = read_varint(&tx[offset..]);
            offset += v + (length * (t & 7 == 2) as usize);
        }
    }

    wagmi(tx[offset] & 7, 2)?; // LEN
    wagmi(tx[offset] >> 3, 11)?; // 11:
    offset += 1;
    let (_, v) = read_varint(&tx[offset..]);
    offset += v;

    wagmi(tx[offset] & 7, 0)?; // VARINT
    wagmi(tx[offset] >> 3, 1)?; // 1: (we enter the contract protobuf)
    offset += 1;
    let (call_type, v) = read_varint(&tx[offset..]);
    offset += v;

    wagmi(call_type, 31); // TriggerSmartContract

    wagmi(tx[offset] & 7, 2)?; // LEN
    wagmi(tx[offset] >> 3, 2)?; // 2:
    offset += 1;
    let (_, v) = read_varint(&tx[offset..]);
    offset += v;

    wagmi(tx[offset] & 7, 2)?; // LEN
    wagmi(tx[offset] >> 3, 1)?; // 1:
    offset += 1;
    let (_, v) = read_varint(&tx[offset..]);
    offset += v;

    wagmi(tx[offset] & 7, 2)?; // LEN
    wagmi(tx[offset] >> 3, 2)?; // 2:
    offset += 1;
    let (_, v) = read_varint(&tx[offset..]);
    offset += v;

    wagmi(tx[offset] & 7, 2)?; // LEN
    wagmi(tx[offset] >> 3, 1)?; // 1:
    offset += 1;
    let (_, v) = read_varint(&tx[offset..]);
    offset += v;

    wagmi(tx[offset] & 7, 2)?; // LEN
    wagmi(tx[offset] >> 3, 2)?; // 2:
    offset += 1;
    let (length, v) = read_varint(&tx[offset..]);
    offset += v;

    // USDT smart contract TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
    wagmi(
        &tx[offset..offset + length],
        &hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"),
    )?;
    offset += length;

    wagmi(tx[offset] & 7, 2)?; // LEN
    wagmi(tx[offset] >> 3, 4)?; // 4:
    offset += 1;
    let (length, v) = read_varint(&tx[offset..]);
    offset += v;

    let data = &tx[offset..offset + length];
    wagmi(&data[..4], &hex!("a9059cbb"))?;

    let mut to = [0u8; 20];
    to.copy_from_slice(&data[16..36]);

    let mut value_bytes = [0u8; 8];
    value_bytes.copy_from_slice(&data[60..68]);
    let value = u64::from_le_bytes(value_bytes);

    Some(UsdtTransfer { to, value })
}

type InflowSet = sol! {
    tuple(address, uint64)[]
};

pub fn main() {
    let tx_count = sp1_zkvm::io::read::<u32>();

    let mut txs = Vec::new();
    for _ in 0..tx_count {
        // txs must be inputted in such an order that
        // their SHA256 hashes are sorted alphabetically
        txs.push(sp1_zkvm::io::read_vec());
    }

    let tx_hashes: Vec<Vec<u8>> = txs.iter().map(|tx| hash(tx)).collect();

    let tx_root = create_merkle_tree(&tx_hashes);
    sp1_zkvm::io::commit_slice(&tx_root);
}
