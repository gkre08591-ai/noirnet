// builder.rs — збірка транзакцій

use super::WalletResult;
use noirnet_crypto::{
    commitment::value_commitment,
    encryption::random_bytes,
    keys::{create_binding_sig, Ed25519Keypair},
    stealth::encrypt_note,
};
use noirnet_types::{
    address::{PaymentAddress, SpendingKey},
    hash::Hash32,
    note::{Note, OutputDescription, SpendDescription},
    transaction::Transaction,
};
use noirnet_zk::proof::{setup_nova, generate_multi_spend_proof};

pub struct TxBuilder;

impl TxBuilder {
    pub fn build_transfer(
        sk: &SpendingKey,
        recipient: &PaymentAddress,
        amount: u64,
        fee: u64,
        // In reality, we need UTXOs. For POC we mock it.
        mock_input_value: u64,
    ) -> WalletResult<Transaction> {
        let fvk = sk.to_fvk();
        let _change_value = mock_input_value - amount - fee;

        // 1. Outputs
        let mut outputs = Vec::new();
        let mut out_cvs = Vec::new();

        // Recipient output
        let out_rcm = random_bytes::<32>();
        let out_rho = random_bytes::<32>();
        let out_note = Note::new(
            amount,
            out_rcm,
            out_rho,
            recipient.pk_d,
            recipient.diversifier,
        );

        let out_enc = encrypt_note(&out_note, &recipient.pk_d, &fvk.ovk);
        let out_cv = value_commitment(amount, &random_bytes::<32>());

        outputs.push(OutputDescription {
            note_commitment: out_note.commitment(),
            ephemeral_key: out_enc.ephemeral_key,
            enc_ciphertext: out_enc.enc_ciphertext,
            out_ciphertext: out_enc.out_ciphertext,
            cv: out_cv,
        });
        out_cvs.push(out_cv);

        // Change output (omitted for brevity, similar to above)

        // 2. Spends
        let mut spends = Vec::new();
        let mut spend_cvs = Vec::new();

        let spend_cv = value_commitment(mock_input_value, &random_bytes::<32>());
        spend_cvs.push(spend_cv);

        // Dummy ZK Proof for all spends
        let pp = setup_nova();
        let dummy_nullifier = Hash32::blake3_of(b"dummy_nf");
        
        let values = [mock_input_value];
        let sks = [1u64];
        let nullifiers = [2u64];
        
        let proof = generate_multi_spend_proof(
            &pp,
            &values,
            &sks,
            &nullifiers,
        )
        .unwrap();

        let spend_kp = Ed25519Keypair::generate();

        spends.push(SpendDescription {
            anchor: Hash32::ZERO,
            nullifier: dummy_nullifier,
            rk: spend_kp.public_key_bytes(),
            cv: spend_cv,
            spend_auth_sig: [0u8; 64], // Needs actual signing of tx hash
        });

        // 3. Assemble Tx
        let mut tx = Transaction {
            version: 1,
            chain_id: 1,
            spends,
            outputs,
            fee,
            gas_limit: 21000,
            memo: None,
            contract_call: None,
            deploy_contract: None,
            binding_sig: [0u8; 64],
            timestamp: Transaction::now_obfuscated(),
            aggregate_spend_proof: proof,
        };

        // 4. Binding Signature
        let signing_bytes = tx.signing_bytes();
        let bsig = create_binding_sig(&spend_cvs, &out_cvs, &sk.sk, &signing_bytes);
        tx.binding_sig = bsig;

        // Note: We also need to sign spend_auth_sig here using `spend_kp` over the tx hash.

        Ok(tx)
    }

    /// Створити транзакцію для розгортання WASM смарт-контракту
    pub fn build_contract_deploy(
        sk: &SpendingKey,
        bytecode: Vec<u8>,
        fee: u64,
        gas_limit: u64,
        mock_input_value: u64,
    ) -> WalletResult<Transaction> {
        let spend_cv = value_commitment(mock_input_value, &random_bytes::<32>());

        // ZK proof для spend
        let pp = setup_nova();
        let proof = generate_multi_spend_proof(
            &pp,
            &[mock_input_value],
            &[1u64],
            &[2u64],
        )
        .unwrap();

        let spend_kp = Ed25519Keypair::generate();
        let dummy_nullifier = Hash32::blake3_of(b"deploy_nf");

        let spends = vec![SpendDescription {
            anchor: Hash32::ZERO,
            nullifier: dummy_nullifier,
            rk: spend_kp.public_key_bytes(),
            cv: spend_cv,
            spend_auth_sig: [0u8; 64],
        }];

        let mut tx = Transaction {
            version: 1,
            chain_id: 1,
            spends,
            outputs: vec![],
            fee,
            gas_limit,
            memo: None,
            contract_call: None,
            deploy_contract: Some(bytecode),
            binding_sig: [0u8; 64],
            timestamp: Transaction::now_obfuscated(),
            aggregate_spend_proof: proof,
        };

        let signing_bytes = tx.signing_bytes();
        let bsig = create_binding_sig(&[spend_cv], &[], &sk.sk, &signing_bytes);
        tx.binding_sig = bsig;

        Ok(tx)
    }

    /// Створити транзакцію для виклику методу смарт-контракту
    pub fn build_contract_call(
        sk: &SpendingKey,
        contract_id: Hash32,
        method: String,
        args: Vec<u8>,
        fee: u64,
        gas_limit: u64,
        mock_input_value: u64,
    ) -> WalletResult<Transaction> {
        use noirnet_types::transaction::ContractCall;

        let spend_cv = value_commitment(mock_input_value, &random_bytes::<32>());
        let caller_commitment = Hash32::blake3_of(&sk.sk).0;

        // ZK proof для spend
        let pp = setup_nova();
        let proof = generate_multi_spend_proof(
            &pp,
            &[mock_input_value],
            &[1u64],
            &[2u64],
        )
        .unwrap();

        let spend_kp = Ed25519Keypair::generate();
        let dummy_nullifier = Hash32::blake3_of(b"call_nf");

        let spends = vec![SpendDescription {
            anchor: Hash32::ZERO,
            nullifier: dummy_nullifier,
            rk: spend_kp.public_key_bytes(),
            cv: spend_cv,
            spend_auth_sig: [0u8; 64],
        }];

        let call = ContractCall {
            contract_id,
            method,
            args,
            gas_limit,
            caller_commitment,
        };

        let mut tx = Transaction {
            version: 1,
            chain_id: 1,
            spends,
            outputs: vec![],
            fee,
            gas_limit,
            memo: None,
            contract_call: Some(call),
            deploy_contract: None,
            binding_sig: [0u8; 64],
            timestamp: Transaction::now_obfuscated(),
            aggregate_spend_proof: proof,
        };

        let signing_bytes = tx.signing_bytes();
        let bsig = create_binding_sig(&[spend_cv], &[], &sk.sk, &signing_bytes);
        tx.binding_sig = bsig;

        Ok(tx)
    }
}
