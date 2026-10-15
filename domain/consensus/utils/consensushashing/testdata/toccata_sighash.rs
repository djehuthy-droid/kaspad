use kaspa_consensus_core::{
    hashing::{sighash::{calc_schnorr_signature_hash, calc_ecdsa_signature_hash, SigHashReusedValuesUnsync}, sighash_type::SigHashType},
    subnets::SubnetworkId,
    tx::{CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use kaspa_hashes::Hash;

fn main() {
    let script = ScriptPublicKey::from_vec(0, vec![0x51]);
    let mut lane = [0; 20]; lane[0] = 0x97; lane[1] = 0xb1;
    println!("[");
    let mut first = true;
    for (version, covenant) in [(0, false), (1, false), (1, true)] {
        let inputs = (0..2).map(|i| {
            let outpoint = TransactionOutpoint::new(Hash::from_bytes([0x11 * (i + 1) as u8; 32]), i);
            if version == 0 { TransactionInput::new(outpoint, vec![], 7 + i as u64, 3) }
            else { TransactionInput::new_with_compute_budget(outpoint, vec![], 7 + i as u64, 20 + i as u16) }
        }).collect();
        let mut outputs: Vec<_> = [300000000, 300000000, 200000000].into_iter().map(|v| TransactionOutput::new(v, script.clone())).collect();
        if covenant { outputs[1].covenant = Some(CovenantBinding::new(1, Hash::from_bytes([0xaa; 32]))); }
        let tx = Transaction::new(version, inputs, outputs, 11, SubnetworkId::from_bytes(lane), 0, vec![0x93, 1, 2, 3]);
        let populated = PopulatedTransaction::new(&tx, vec![UtxoEntry::new(400010000, script.clone(), 0, false, None); 2]);
        for index in 0..2 {
            for mode in [1, 2, 4, 129, 130, 132] {
                let hash_type = SigHashType::from_u8(mode).unwrap();
                let schnorr = calc_schnorr_signature_hash(&populated, index, hash_type, &SigHashReusedValuesUnsync::new());
                let ecdsa = calc_ecdsa_signature_hash(&populated, index, hash_type, &SigHashReusedValuesUnsync::new());
                if !first { println!(","); } first = false;
                print!("  {{\"version\":{version},\"covenant\":{covenant},\"input\":{index},\"mode\":{mode},\"schnorr\":\"{schnorr}\",\"ecdsa\":\"{ecdsa}\"}}");
            }
        }
    }
    println!("\n]");
}
