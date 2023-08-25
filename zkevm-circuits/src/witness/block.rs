use super::{ExecStep, Rw, RwMap, Transaction};
use crate::{
    table::BlockContextFieldTag,
    util::{word},
};
use bus_mapping::{
    circuit_input_builder::{self, CopyEvent, ExpEvent, FixedCParams},
    state_db::CodeDB,
};
use eth_types::{Address, Field, ToScalar, Word};
use halo2_proofs::circuit::Value;

// TODO: Remove fields that are duplicated in`eth_block`
/// Block is the struct used by all circuits, which contains all the needed
/// data for witness generation.
#[derive(Debug, Clone, Default)]
pub struct Block<F> {
    /// The randomness for random linear combination
    pub randomness: F,
    /// Transactions in the block
    pub txs: Vec<Transaction>,
    /// EndBlock step that is repeated after the last transaction and before
    /// reaching the last EVM row.
    pub end_block_not_last: ExecStep,
    /// Last EndBlock step that appears in the last EVM row.
    pub end_block_last: ExecStep,
    /// Read write events in the RwTable
    pub rws: RwMap,
    /// Bytecode used in the block
    pub bytecodes: CodeDB,
    /// The block context
    pub context: BlockContext,
    /// Copy events for the copy circuit's table.
    pub copy_events: Vec<CopyEvent>,
    /// Exponentiation traces for the exponentiation circuit's table.
    pub exp_events: Vec<ExpEvent>,
    /// Pad exponentiation circuit to make selectors fixed.
    pub exp_circuit_pad_to: usize,
    /// Circuit Setup Parameters
    pub circuits_params: FixedCParams,
    /// Inputs to the SHA3 opcode
    pub sha3_inputs: Vec<Vec<u8>>,
    /// State root of the previous block
    pub prev_state_root: Word, // TODO: Make this H256
    /// Keccak inputs
    pub keccak_inputs: Vec<Vec<u8>>,
    /// Original Block from geth
    pub eth_block: eth_types::Block<eth_types::Transaction>,
}

impl<F: Field> Block<F> {
    /// For each tx, for each step, print the rwc at the beginning of the step,
    /// and all the rw operations of the step.
    #[allow(dead_code, reason = "useful debug function")]
    pub(crate) fn debug_print_txs_steps_rw_ops(&self) {
        for (tx_idx, tx) in self.txs.iter().enumerate() {
            println!("tx {}", tx_idx);
            for step in tx.steps() {
                println!(" step {:?} rwc: {}", step.exec_state, step.rwc.0);
                for rw_idx in 0..step.bus_mapping_instance.len() {
                    println!("  - {:?}", self.get_rws(step, rw_idx));
                }
            }
        }
    }

    /// Get a read-write record
    pub(crate) fn get_rws(&self, step: &ExecStep, index: usize) -> Rw {
        self.rws[step.rw_index(index)]
    }
}

/// Block context for execution
#[derive(Debug, Default, Clone)]
pub struct BlockContext {
    /// The address of the miner for the block
    pub coinbase: Address,
    /// The gas limit of the block
    pub gas_limit: u64,
    /// The number of the block
    pub number: Word,
    /// The timestamp of the block
    pub timestamp: Word,
    /// The difficulty of the blcok
    pub difficulty: Word,
    /// The base fee, the minimum amount of gas fee for a transaction
    pub base_fee: Word,
    /// The hash of previous blocks
    pub history_hashes: Vec<Word>,
    /// The chain id
    pub chain_id: Word,
}

impl BlockContext {
    /// Assignments for block table
    pub fn table_assignments<F: Field>(&self) -> Vec<[Value<F>; 4]> {
        [
            vec![
                [
                    Value::known(F::from(BlockContextFieldTag::Coinbase as u64)),
                    Value::known(F::ZERO),
                    Value::known(word::Word::from(self.coinbase).lo()),
                    Value::known(word::Word::from(self.coinbase).hi()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Timestamp as u64)),
                    Value::known(F::ZERO),
                    Value::known(self.timestamp.to_scalar().unwrap()),
                    Value::known(F::ZERO),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Number as u64)),
                    Value::known(F::ZERO),
                    Value::known(self.number.to_scalar().unwrap()),
                    Value::known(F::ZERO),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Difficulty as u64)),
                    Value::known(F::ZERO),
                    Value::known(word::Word::from(self.difficulty).lo()),
                    Value::known(word::Word::from(self.difficulty).hi()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::GasLimit as u64)),
                    Value::known(F::ZERO),
                    Value::known(F::from(self.gas_limit)),
                    Value::known(F::ZERO),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::BaseFee as u64)),
                    Value::known(F::ZERO),
                    Value::known(word::Word::from(self.base_fee).lo()),
                    Value::known(word::Word::from(self.base_fee).hi()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::ChainId as u64)),
                    Value::known(F::ZERO),
                    Value::known(word::Word::from(self.chain_id).lo()),
                    Value::known(word::Word::from(self.chain_id).hi()),
                ],
            ],
            {
                let len_history = self.history_hashes.len();
                self.history_hashes
                    .iter()
                    .enumerate()
                    .map(|(idx, hash)| {
                        [
                            Value::known(F::from(BlockContextFieldTag::BlockHash as u64)),
                            Value::known((self.number - len_history + idx).to_scalar().unwrap()),
                            Value::known(word::Word::from(*hash).lo()),
                            Value::known(word::Word::from(*hash).hi()),
                        ]
                    })
                    .collect()
            },
        ]
        .concat()
    }
}

impl From<&circuit_input_builder::Block> for BlockContext {
    fn from(block: &circuit_input_builder::Block) -> Self {
        Self {
            coinbase: block.coinbase,
            gas_limit: block.gas_limit,
            number: block.number,
            timestamp: block.timestamp,
            difficulty: block.difficulty,
            base_fee: block.base_fee,
            history_hashes: block.history_hashes.clone(),
            chain_id: block.chain_id,
        }
    }
}
