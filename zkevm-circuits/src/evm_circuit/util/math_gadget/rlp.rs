use crate::{
    evm_circuit::util::rlc,
    util::word::{Word32Cell, WordExpr},
};
use eth_types::{Address, Field, ToScalar, Word};
use gadgets::util::{and, expr_from_bytes, not, select, sum, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::{
        param::{N_BYTES_U64, N_BYTES_WORD},
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            AccountAddress, CachedRegion, Cell, RandomLinearCombination,
        },
    },
    util::word,
};

use super::IsZeroGadget;

#[derive(Clone, Debug)]
pub struct RlpU64Gadget<F> {
    /// Byte representation of the U64 value.
    value_rlc: RandomLinearCombination<F, N_BYTES_U64>,
    /// Flag to mark the most significant byte in the U64's byte representation.
    is_most_significant_byte: [Cell<F>; N_BYTES_U64],
    /// Whether the most significant byte is zero, to check for zero value.
    most_significant_byte_is_zero: IsZeroGadget<F>,
    /// Boolean flag to mark whether or not the U64 value is less than 128.
    is_lt_128: Cell<F>,
}

impl<F: Field> RlpU64Gadget<F> {
    /// Configure and construct a gadget for RLP-encoding of a U64 value.
    fn construct(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let value_rlc = cb.query_keccak_rlc();

        let is_most_significant_byte = array_init::array_init(|_| cb.query_bool());
        cb.require_boolean(
            "at most one of is_most_significant_byte is one",
            sum::expr(&is_most_significant_byte),
        );

        let most_significant_byte = sum::expr(
            value_rlc
                .cells
                .iter()
                .zip(&is_most_significant_byte)
                .map(|(byte, indicator)| byte.expr() * indicator.expr()),
        );
        let most_significant_byte_is_zero = IsZeroGadget::construct(cb, most_significant_byte);
        let is_lt_128 = cb.query_bool();

        let value = expr_from_bytes(&value_rlc.cells);
        cb.condition(most_significant_byte_is_zero.expr(), |cb| {
            cb.require_zero("if most significant byte is 0, value is 0", value.clone());
            cb.require_zero(
                "if most significant byte is 0, value is less than 128",
                1.expr() - is_lt_128.expr(),
            );
        });

        for (i, is_most_significant) in is_most_significant_byte.iter().enumerate() {
            cb.condition(is_most_significant.expr(), |cb| {
                cb.require_equal(
                    "most significant byte is non-zero",
                    most_significant_byte_is_zero.expr(),
                    0.expr(),
                );
                cb.require_equal(
                    "higher bytes are 0",
                    expr_from_bytes(&value_rlc.cells[0..(i + 1)]),
                    value.clone(),
                );
            });
        }

        // If is_lt_128, then value < 128, checked by a lookup.

        // Otherwise, then value >= 128, checked as follows:
        // - Either the first byte is not the most significant, and there is a more significant one;
        // - Or the first byte is the most significant, and it is >= 128. value ∈ [128, 256) (value
        //   - 128) ∈ [0, 128)
        let byte_128 = value_rlc.cells[0].expr() - 128.expr();
        let is_first = is_most_significant_byte[0].expr();
        let byte_128_or_zero = byte_128 * is_first;

        let value_lt_128 = select::expr(is_lt_128.expr(), value, byte_128_or_zero);
        cb.range_lookup(value_lt_128, 128);

        Self {
            value_rlc,
            is_most_significant_byte,
            most_significant_byte_is_zero,
            is_lt_128,
        }
    }

    /// Assign witness data to the RlpU64 gadget.
    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: u64,
    ) -> Result<(), Error> {
        let value_bytes = value.to_le_bytes();

        let most_significant_byte_index = value_bytes
            .iter()
            .rev()
            .position(|&byte| byte != 0)
            .map(|i| N_BYTES_U64 - i - 1);
        self.most_significant_byte_is_zero.assign(
            region,
            offset,
            most_significant_byte_index
                .map(|i| F::from(value_bytes[i] as u64))
                .unwrap_or_default(),
        )?;

        self.value_rlc.assign(region, offset, Some(value_bytes))?;

        for i in 0..N_BYTES_U64 {
            self.is_most_significant_byte[i].assign(
                region,
                offset,
                Value::known(
                    (Some(i) == most_significant_byte_index)
                        .to_scalar()
                        .unwrap(),
                ),
            )?;
        }

        self.is_lt_128.assign(
            region,
            offset,
            Value::known((value < 128).to_scalar().unwrap()),
        )?;

        Ok(())
    }

    /// Value of the U64 as an expression.
    fn value(&self) -> Expression<F> {
        expr_from_bytes(&self.value_rlc.cells)
    }

    /// Minimum number of bytes it takes to represent the U64 value.
    fn n_bytes(&self) -> Expression<F> {
        sum::expr(
            self.is_most_significant_byte
                .iter()
                .enumerate()
                .map(|(i, indicator)| (1 + i).expr() * indicator.expr()),
        )
    }

    /// Length of the RLP-encoding of the U64 value.
    fn rlp_length(&self) -> Expression<F> {
        1.expr() + (not::expr(self.is_lt_128.expr()) * self.n_bytes())
    }

    /// RLC for the RLP-encoding of the U64 value.
    fn rlp_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        select::expr(
            and::expr([
                self.is_lt_128.expr(),
                not::expr(self.most_significant_byte_is_zero.expr()),
            ]),
            self.value(),
            (0x80.expr() + self.n_bytes()) * self.challenge_power_n_bytes(cb)
                + self.value_rlc.expr(),
        )
    }

    fn challenge_power_rlp_length(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        cb.challenges().keccak_input()
            * select::expr(
                self.is_lt_128.expr(),
                1.expr(),
                self.challenge_power_n_bytes(cb),
            )
    }

    fn challenge_power_n_bytes(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        select::expr(
            self.most_significant_byte_is_zero.expr(),
            1.expr(),
            sum::expr(
                self.is_most_significant_byte
                    .iter()
                    .zip(cb.challenges().keccak_powers_of_randomness::<N_BYTES_U64>())
                    .map(|(indicator, power)| indicator.expr() * power.expr()),
            ),
        )
    }
}

#[derive(Clone, Debug)]
pub struct ContractCreateGadget<F, const IS_CREATE2: bool> {
    /// Sender address of the contract creation tx.
    caller_address: AccountAddress<F>,
    /// Sender nonce of the contract creation tx.
    nonce: RlpU64Gadget<F>,
    /// Keccak256 hash of init code, used for CREATE2. We don't use a
    /// RandomLinearCombination here since we require both keccak and word
    /// RLC in the case of init code hash, for BeginTx and
    /// CREATE2 respectively. Instead, we store just the bytes and calculate the
    /// appropriate RLC wherever needed.
    code_hash: Word32Cell<F>,
    /// Random salt for CREATE2.
    salt: Word32Cell<F>,
}

impl<F: Field, const IS_CREATE2: bool> ContractCreateGadget<F, IS_CREATE2> {
    /// Configure and construct the gadget.
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let caller_address = cb.query_account_address();
        let nonce = RlpU64Gadget::construct(cb);
        let code_hash = cb.query_word32();
        let salt = cb.query_word32();

        Self {
            caller_address,
            nonce,
            code_hash,
            salt,
        }
    }

    /// Assign witness data to the ContractCreate gadget.
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        caller_address: Address,
        caller_nonce: u64,
        code_hash: Option<Word>,
        salt: Option<Word>,
    ) -> Result<(), Error> {
        let mut caller_address_bytes = caller_address.to_fixed_bytes();
        caller_address_bytes.reverse();
        self.caller_address
            .assign(region, offset, Some(caller_address_bytes))?;

        self.nonce.assign(region, offset, caller_nonce)?;

        self.code_hash
            .assign_u256(region, offset, code_hash.unwrap_or_default())?;

        self.salt
            .assign_u256(region, offset, salt.unwrap_or_default())?;

        Ok(())
    }

    /// Caller address' value.
    pub(crate) fn caller_address(&self) -> word::Word<Expression<F>> {
        self.caller_address.to_word()
    }

    /// Caller nonce's value.
    pub(crate) fn caller_nonce(&self) -> Expression<F> {
        self.nonce.value()
    }

    /// Code hash word RLC.
    pub(crate) fn code_hash(&self) -> word::Word<Expression<F>> {
        self.code_hash.to_word()
    }

    /// Code hash keccak RLC.
    pub(crate) fn code_hash_keccak_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        cb.keccak_rlc::<N_BYTES_WORD>(
            self.code_hash
                .limbs
                .iter()
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }

    pub(crate) fn salt(&self) -> word::Word<Expression<F>> {
        self.salt.to_word()
    }

    /// Salt keccak RLC.
    pub(crate) fn salt_keccak_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        cb.keccak_rlc::<N_BYTES_WORD>(
            self.salt
                .limbs
                .iter()
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }

    /// Caller address' RLC value.
    pub(crate) fn caller_address_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        rlc::expr(
            &self.caller_address.limbs.clone().map(|x| x.expr()),
            cb.challenges().keccak_input(),
        )
    }

    /// Length of the input data to the keccak hash function.
    pub(crate) fn input_length(&self) -> Expression<F> {
        if IS_CREATE2 {
            // | 0xff | caller_address | salt | code_hash |
            // |------|----------------|------|-----------|
            // | 1    | 20             | 32   | 32        |
            (1 + 20 + 32 + 32).expr()
        } else {
            // | prefix | addr-prefix | addr | nonce-bytes       |
            // |--------|-------------|------|-------------------|
            // | 1      | 1           | 20   | rlp_length(nonce) |
            22.expr() + self.nonce.rlp_length()
        }
    }

    /// RLC for the input data.
    pub(crate) fn input_rlc(&self, cb: &EVMConstraintBuilder<F>) -> Expression<F> {
        let challenges = cb.challenges().keccak_powers_of_randomness::<21>();
        let challenge_power_20 = challenges[19].clone();
        if IS_CREATE2 {
            // RLC(le-bytes([0xff | caller_address | salt | code_hash]))
            //
            // | 0xff | caller address | salt | init code hash |
            // |------|----------------|------|----------------|
            // | 1    | 20             | 32   | 32             |
            let challenge_power_16 = challenges[15].clone();
            let challenge_power_32 = challenge_power_16.square();
            let challenge_power_64 = challenge_power_32.clone().square();
            let challenge_power_84 = challenge_power_64.clone() * challenge_power_20;
            (0xff.expr() * challenge_power_84)
                + (self.caller_address_rlc(cb) * challenge_power_64)
                + (self.salt_keccak_rlc(cb) * challenge_power_32)
                + self.code_hash_keccak_rlc(cb)
        } else {
            // RLC(RLP([caller_address, caller_nonce]))
            let challenge_power_21 = challenges[20].clone();
            ((self.caller_address_rlc(cb)
                + (148.expr() * challenge_power_20)
                + ((213.expr() + self.nonce.rlp_length()) * challenge_power_21))
                * self.nonce.challenge_power_rlp_length(cb))
                + self.nonce.rlp_rlc(cb)
        }
    }
}

