use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{
            N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE,
            N_BYTES_U64, N_BYTES_WORD,
        },
        step::ExecutionState,
        util::{
            common_gadget::TransferGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{
                ConstantDivisionGadget, ContractCreateGadget, IsZeroGadget, IsZeroWordGadget,
                LtGadget, LtWordGadget,
            },
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryExpansionGadget,
            },
            not, AccountAddress, CachedRegion, Cell, Word, WordExpr,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::{
        word::{Word32Cell, WordCell},
        Expr,
    },
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId, state_db::CodeDB};
use eth_types::{
    evm_types::{GasCost, INIT_CODE_WORD_GAS},
    Field, ToBigEndian, ToScalar, U256,
};
use ethers_core::utils::keccak256;
use gadgets::util::{and, or, select};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use std::iter::once;

/// Gadget for CREATE and CREATE2 opcodes
#[derive(Clone, Debug)]
pub(crate) struct CreateGadget<F, const IS_CREATE2: bool, const S: ExecutionState> {
    opcode: Cell<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    depth: Cell<F>,

    is_create2: IsZeroGadget<F>,
    is_success: Cell<F>,
    was_warm: Cell<F>,
    value: Word32Cell<F>,

    caller_balance: WordCell<F>,
    callee_reversion_info: ReversionInfo<F>,
    callee_nonce: Cell<F>,
    prev_code_hash: WordCell<F>,
    transfer: TransferGadget<F>,
    create: ContractCreateGadget<F, IS_CREATE2>,

    init_code: MemoryAddressGadget<F>,
    init_code_word_size: ConstantDivisionGadget<F, N_BYTES_MEMORY_ADDRESS>,
    init_code_rlc: Cell<F>,
    keccak_output: Word32Cell<F>,

    is_depth_in_range: LtGadget<F, N_BYTES_U64>,
    is_insufficient_balance: LtWordGadget<F>,
    is_nonce_in_range: LtGadget<F, N_BYTES_U64>,
    not_address_collision: IsZeroWordGadget<F, Word<Expression<F>>>,

    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    gas_left: ConstantDivisionGadget<F, N_BYTES_GAS>,
}

impl<F: Field, const IS_CREATE2: bool, const S: ExecutionState> ExecutionGadget<F>
    for CreateGadget<F, IS_CREATE2, S>
{
    const NAME: &'static str = "CREATE";

    const EXECUTION_STATE: ExecutionState = S;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());
        cb.require_in_set(
            "Opcode is CREATE or CREATE2",
            opcode.expr(),
            vec![OpcodeId::CREATE2.expr(), OpcodeId::CREATE.expr()],
        );
        let is_create2 = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CREATE2.expr());

        // Use rw_counter of the step which triggers next call as its call_id.
        let callee_call_id = cb.curr.state.rw_counter.clone();
        let current_call_id = cb.curr.state.call_id.clone();
        let is_success = cb.query_bool();

        // read from call context
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let depth = cb.call_context(None, CallContextFieldTag::Depth);
        let mut reversion_info = cb.reversion_info_read(None);

        let keccak_output = cb.query_word32();
        let create = ContractCreateGadget::construct(cb);
        let contract_addr = AccountAddress::new(
            keccak_output.limbs[..N_BYTES_ACCOUNT_ADDRESS]
                .to_vec()
                .try_into()
                .unwrap(),
        );

        // stack operations
        let value = cb.query_word32();
        let length = cb.query_memory_address();
        let offset = cb.query_word_unchecked();
        cb.stack_pop(value.to_word());
        cb.stack_pop(offset.to_word());
        cb.stack_pop(length.to_word());
        cb.condition(is_create2.expr(), |cb| {
            cb.stack_pop(create.salt());
        });
        cb.stack_push(contract_addr.to_word().mul_selector(is_success.expr()));

        // read caller's balance and nonce
        let caller_nonce = create.caller_nonce();
        let caller_balance = cb.query_word_unchecked();
        cb.account_read(
            create.caller_address(),
            AccountFieldTag::Balance,
            caller_balance.to_word(),
        );
        cb.account_read(
            create.caller_address(),
            AccountFieldTag::Nonce,
            Word::from_lo_unchecked(caller_nonce.expr()),
        );

        // Pre-check: call depth, user's nonce and user's balance
        let is_depth_in_range = LtGadget::construct(cb, depth.expr(), 1025.expr());
        let is_insufficient_balance =
            LtWordGadget::construct(cb, &caller_balance.to_word(), &value.to_word());
        let is_nonce_in_range = LtGadget::construct(cb, caller_nonce.expr(), u64::MAX.expr());
        let is_precheck_ok = and::expr([
            is_depth_in_range.expr(),
            not::expr(is_insufficient_balance.expr()),
            is_nonce_in_range.expr(),
        ]);

        // verify gas cost
        let init_code = MemoryAddressGadget::construct(cb, offset, length);
        let memory_expansion = MemoryExpansionGadget::construct(cb, [init_code.address()]);
        let init_code_word_size = ConstantDivisionGadget::construct(
            cb,
            init_code.length() + (N_BYTES_WORD - 1).expr(),
            N_BYTES_WORD as u64,
        );
        let keccak_gas_cost = init_code_word_size.quotient()
            * select::expr(
                is_create2.expr(),
                (INIT_CODE_WORD_GAS + GasCost::COPY_SHA3).expr(),
                INIT_CODE_WORD_GAS.expr(),
            );
        let gas_cost = GasCost::CREATE.expr() + memory_expansion.gas_cost() + keccak_gas_cost;
        let gas_remaining = cb.curr.state.gas_left.expr() - gas_cost.clone();
        let gas_left = ConstantDivisionGadget::construct(cb, gas_remaining.clone(), 64);
        let callee_gas_left = gas_remaining - gas_left.quotient();

        let was_warm = cb.query_bool();
        let init_code_rlc = cb.query_cell_phase2();
        let prev_code_hash = cb.query_word_unchecked();
        let callee_nonce = cb.query_cell();
        let not_address_collision = cb.condition(is_precheck_ok.expr(), |cb| {
            // increase caller's nonce
            cb.account_write(
                create.caller_address(),
                AccountFieldTag::Nonce,
                Word::from_lo_unchecked(caller_nonce.expr() + 1.expr()),
                Word::from_lo_unchecked(caller_nonce.expr()),
                Some(&mut reversion_info),
            );

            // add callee to access list
            cb.account_access_list_write_unchecked(
                tx_id.expr(),
                contract_addr.to_word(),
                1.expr(),
                was_warm.expr(),
                Some(&mut reversion_info),
            );

            // read contract's previous hash
            cb.account_read(
                contract_addr.to_word(),
                AccountFieldTag::CodeHash,
                prev_code_hash.to_word(),
            );

            // ErrContractAddressCollision, if any one of following criteria meets.
            // Nonce is not zero or account code hash is not either 0 or EMPTY_CODE_HASH.
            // Here use `isZeroWord(callee_nonce + prev_code_hash_word * (prev_code_hash_word -
            // empty_code_hash_word))` to represent `(callee_nonce == 0 && (prev_code_hash_word == 0
            // or prev_code_hash_word == empty_code_hash_word))`
            let prev_code_hash_word = prev_code_hash.to_word();
            IsZeroWordGadget::construct(
                cb,
                &Word::from_lo_unchecked(callee_nonce.expr()).add_unchecked(
                    prev_code_hash_word
                        .clone()
                        .mul_unchecked(prev_code_hash_word.sub_unchecked(cb.empty_code_hash())),
                ),
            )
        });

        for (field_tag, value) in [
            (
                CallContextFieldTag::ProgramCounter,
                Word::from_lo_unchecked(cb.curr.state.program_counter.expr() + 1.expr()),
            ),
            (
                CallContextFieldTag::StackPointer,
                Word::from_lo_unchecked(
                    cb.curr.state.stack_pointer.expr() + 2.expr() + is_create2.expr(),
                ),
            ),
            (
                CallContextFieldTag::GasLeft,
                Word::from_lo_unchecked(gas_left.quotient()),
            ),
            (
                CallContextFieldTag::MemorySize,
                Word::from_lo_unchecked(memory_expansion.next_memory_word_size()),
            ),
            (
                CallContextFieldTag::ReversibleWriteCounter,
                Word::from_lo_unchecked(cb.curr.state.reversible_write_counter.expr() + 2.expr()),
            ),
        ] {
            cb.call_context_lookup_write(None, field_tag, value);
        }

        let mut callee_reversion_info =
            cb.reversion_info_write_unchecked(Some(callee_call_id.expr()));
        let transfer = cb.condition(
            and::expr([is_precheck_ok.clone(), not_address_collision.expr()]),
            |cb| {
                cb.condition(init_code.has_length(), |cb| {
                    // the init code is being copied from memory to bytecode, so a copy table lookup
                    // to verify that the associated fields for the copy event.
                    cb.copy_table_lookup(
                        Word::from_lo_unchecked(current_call_id.expr()),
                        CopyDataType::Memory.expr(),
                        create.code_hash(),
                        CopyDataType::Bytecode.expr(),
                        init_code.offset(),
                        init_code.address(),
                        0.expr(),             // dst_addr
                        init_code.length(),   // length
                        init_code_rlc.expr(), // rlc_acc
                        init_code.length(),   // rwc_inc
                    );
                });

                // keccak table lookup to verify contract address.
                cb.keccak_table_lookup(
                    create.input_rlc(cb),
                    create.input_length(),
                    keccak_output.to_word(),
                );

                // propagate is_persistent
                cb.require_equal(
                    "callee_is_persistent == is_persistent ⋅ is_success",
                    callee_reversion_info.is_persistent(),
                    reversion_info.is_persistent() * is_success.expr(),
                );

                // transfer
                let transfer = TransferGadget::construct(
                    cb,
                    create.caller_address(),
                    contract_addr.to_word(),
                    0.expr(),
                    1.expr(),
                    value.clone(),
                    &mut callee_reversion_info,
                );

                // EIP 161, the nonce of a newly created contract is 1
                cb.account_write(
                    contract_addr.to_word(),
                    AccountFieldTag::Nonce,
                    Word::one(),
                    Word::zero(),
                    Some(&mut callee_reversion_info),
                );

                cb.condition(init_code.has_length(), |cb| {
                    for (field_tag, value) in [
                        (
                            CallContextFieldTag::CallerId,
                            Word::from_lo_unchecked(current_call_id.expr()),
                        ),
                        (
                            CallContextFieldTag::IsSuccess,
                            Word::from_lo_unchecked(is_success.expr()),
                        ),
                        (
                            CallContextFieldTag::IsPersistent,
                            Word::from_lo_unchecked(callee_reversion_info.is_persistent()),
                        ),
                        (
                            CallContextFieldTag::TxId,
                            Word::from_lo_unchecked(tx_id.expr()),
                        ),
                        (CallContextFieldTag::CallerAddress, create.caller_address()),
                        (CallContextFieldTag::CalleeAddress, contract_addr.to_word()),
                        (
                            CallContextFieldTag::RwCounterEndOfReversion,
                            Word::from_lo_unchecked(
                                callee_reversion_info.rw_counter_end_of_reversion(),
                            ),
                        ),
                        (
                            CallContextFieldTag::Depth,
                            Word::from_lo_unchecked(depth.expr() + 1.expr()),
                        ),
                        (
                            CallContextFieldTag::IsRoot,
                            Word::from_lo_unchecked(false.expr()),
                        ),
                        (
                            CallContextFieldTag::IsStatic,
                            Word::from_lo_unchecked(false.expr()),
                        ),
                        (
                            CallContextFieldTag::IsCreate,
                            Word::from_lo_unchecked(true.expr()),
                        ),
                        (CallContextFieldTag::CodeHash, create.code_hash()),
                    ] {
                        cb.call_context_lookup_write(Some(callee_call_id.expr()), field_tag, value);
                    }

                    cb.require_step_state_transition(StepStateTransition {
                        rw_counter: Delta(cb.rw_counter_offset()),
                        call_id: To(callee_call_id.expr()),
                        is_root: To(false.expr()),
                        is_create: To(true.expr()),
                        code_hash: To(create.code_hash()),
                        gas_left: To(callee_gas_left),
                        reversible_write_counter: To(
                            1.expr() + transfer.reversible_w_delta().expr()
                        ),
                        ..StepStateTransition::new_context()
                    })
                });

                // handle state transition if empty init code
                cb.condition(not::expr(init_code.has_length()), |cb| {
                    for field_tag in [
                        CallContextFieldTag::LastCalleeId,
                        CallContextFieldTag::LastCalleeReturnDataOffset,
                        CallContextFieldTag::LastCalleeReturnDataLength,
                    ] {
                        cb.call_context_lookup_write(None, field_tag, Word::zero());
                    }
                    cb.require_step_state_transition(StepStateTransition {
                        rw_counter: Delta(cb.rw_counter_offset()),
                        program_counter: Delta(1.expr()),
                        stack_pointer: Delta(2.expr() + is_create2.expr()),
                        gas_left: Delta(-gas_cost.expr()),
                        reversible_write_counter: Delta(
                            3.expr() + transfer.reversible_w_delta().expr(),
                        ),
                        ..Default::default()
                    })
                });

                transfer
            },
        );

        cb.condition(
            is_success.expr() * (1.expr() - reversion_info.is_persistent()),
            |cb| {
                cb.require_equal(
                    "callee_rw_counter_end_of_reversion == rw_counter_end_of_reversion-(reversible_write_counter + 1)",
                    callee_reversion_info.rw_counter_end_of_reversion(),
                    reversion_info.rw_counter_of_reversion(1.expr()),
                );
            },
        );

        // Handle the case where an error of ErrDepth, ErrInsufficientBalance,
        // ErrNonceUintOverflow or ErrContractAddressCollision occurred.
        cb.condition(
            or::expr([
                not::expr(is_precheck_ok),
                not::expr(not_address_collision.expr()),
            ]),
            |cb| {
                // Save caller's call state
                for field_tag in [
                    CallContextFieldTag::LastCalleeId,
                    CallContextFieldTag::LastCalleeReturnDataOffset,
                    CallContextFieldTag::LastCalleeReturnDataLength,
                ] {
                    cb.call_context_lookup_write(None, field_tag, Word::zero());
                }

                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(cb.rw_counter_offset()),
                    program_counter: Delta(1.expr()),
                    stack_pointer: Delta(2.expr() + is_create2.expr()),
                    memory_word_size: To(memory_expansion.next_memory_word_size()),
                    gas_left: Delta(-gas_cost.expr()),
                    ..StepStateTransition::default()
                });
            },
        );

        Self {
            opcode,
            reversion_info,
            tx_id,
            was_warm,
            value,
            depth,
            callee_reversion_info,
            transfer,
            init_code,
            init_code_rlc,
            memory_expansion,
            gas_left,
            init_code_word_size,
            create,
            caller_balance,
            is_depth_in_range,
            is_insufficient_balance,
            is_nonce_in_range,
            keccak_output,
            not_address_collision,
            is_success,
            prev_code_hash,
            callee_nonce,
            is_create2,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode().unwrap();
        let is_create2 = opcode == OpcodeId::CREATE2;
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.is_create2.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::CREATE2.as_u64()),
        )?;

        self.tx_id
            .assign(region, offset, Value::known(tx.id.to_scalar().unwrap()))?;
        self.depth.assign(
            region,
            offset,
            Value::known(call.depth.to_scalar().unwrap()),
        )?;
        self.reversion_info.assign(
            region,
            offset,
            block.get_rws(step, 2).call_context_value().as_usize(),
            block.get_rws(step, 3).call_context_value().as_usize() != 0,
        )?;

        // 0..3 : TxId, Depth, RwCounterEndOfReversion and IsPersistent
        // stack value starts from 4
        let [value, init_code_start, init_code_length] =
            [4, 5, 6].map(|idx| block.get_rws(step, idx).stack_value());
        self.value.assign_u256(region, offset, value)?;
        let salt = if is_create2 {
            block.get_rws(step, 7).stack_value()
        } else {
            U256::zero()
        };
        let rw_offset = if is_create2 { 8 } else { 7 };

        // Pre-check: call depth, user's nonce and user's balance
        let (caller_balance, _) = block.get_rws(step, rw_offset + 1).account_value_pair();
        let (caller_nonce, _) = block.get_rws(step, rw_offset + 2).account_value_pair();
        let is_precheck_ok =
            if call.depth < 1025 && caller_balance >= value && caller_nonce.as_u64() < u64::MAX {
                1
            } else {
                0
            };

        self.caller_balance
            .assign_u256(region, offset, caller_balance)?;
        let (callee_prev_code_hash, was_warm) = if is_precheck_ok == 1 {
            let (_, was_warm) = block
                .get_rws(step, rw_offset + 4)
                .tx_access_list_value_pair();
            let (callee_prev_code_hash, _) =
                block.get_rws(step, rw_offset + 5).account_value_pair();
            (callee_prev_code_hash, was_warm)
        } else {
            (U256::from(0), false)
        };

        // 3 RWs while is_precheck_ok is true
        // account_write(caller), tx_access_list_write(callee) and  account_read(callee)
        let [callee_rw_counter_end_of_reversion, callee_is_persistent] = [
            rw_offset + 11 - (1 - is_precheck_ok) * 3,
            rw_offset + 12 - (1 - is_precheck_ok) * 3,
        ]
        .map(|i| block.get_rws(step, i).call_context_value());

        // retrieve code_hash for creating address
        let is_address_collision = !callee_prev_code_hash.is_zero();

        self.prev_code_hash.assign_u256(
            region,
            offset,
            if is_address_collision {
                callee_prev_code_hash
            } else {
                U256::from(0)
            },
        )?;
        self.not_address_collision.assign_u256(
            region,
            offset,
            U256::from(is_address_collision as u8),
        )?;

        // gas cost of memory expansion
        let init_code_address =
            self.init_code
                .assign(region, offset, init_code_start, init_code_length)?;
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [init_code_address],
        )?;
        let (init_code_word_size, _) = self.init_code_word_size.assign(
            region,
            offset,
            (31u64 + init_code_length.as_u64()).into(),
        )?;
        let gas_left = step.gas_left
            - GasCost::CREATE
            - memory_expansion_gas_cost
            - u64::try_from(init_code_word_size).unwrap()
                * if is_create2 {
                    INIT_CODE_WORD_GAS + GasCost::COPY_SHA3
                } else {
                    INIT_CODE_WORD_GAS
                };
        self.gas_left.assign(region, offset, gas_left.into())?;
        self.callee_reversion_info.assign(
            region,
            offset,
            callee_rw_counter_end_of_reversion.low_u64() as usize,
            callee_is_persistent.low_u64() != 0,
        )?;

        // assign witness while pre-check is okay
        let copy_rw_increase = init_code_length.as_usize();
        let code_hash = if is_precheck_ok == 1 {
            // transfer
            let [caller_balance_pair, callee_balance_pair] = if !value.is_zero() {
                [
                    rw_offset + copy_rw_increase + 14,
                    rw_offset + copy_rw_increase + 15,
                ]
                .map(|i| block.get_rws(step, i).account_value_pair())
            } else {
                [(0.into(), 0.into()), (0.into(), 0.into())]
            };
            self.transfer.assign(
                region,
                offset,
                caller_balance_pair,
                callee_balance_pair,
                value,
            )?;

            // copy_table_lookup
            let values: Vec<_> = (rw_offset + 13..rw_offset + 13 + copy_rw_increase)
                .map(|i| block.get_rws(step, i).memory_value())
                .collect();
            let code_hash = CodeDB::hash(&values);
            let keccak_input: Vec<u8> = if is_create2 {
                once(0xffu8)
                    .chain(call.address.to_fixed_bytes())
                    .chain(salt.to_be_bytes())
                    .chain(code_hash.to_fixed_bytes())
                    .collect()
            } else {
                let mut stream = ethers_core::utils::rlp::RlpStream::new();
                stream.begin_list(2);
                stream.append(&call.address);
                stream.append(&caller_nonce);
                stream.out().to_vec()
            };
            let mut keccak_output = keccak256(keccak_input);
            keccak_output.reverse();

            self.keccak_output.assign_u256(
                region,
                offset,
                U256::from_little_endian(&keccak_output),
            )?;
            self.init_code_rlc.assign(
                region,
                offset,
                region.keccak_rlc(&values.iter().rev().cloned().collect::<Vec<u8>>()),
            )?;
            self.was_warm
                .assign(region, offset, Value::known(F::from(was_warm.into())))?;
            self.callee_nonce
                .assign(region, offset, Value::known(F::ZERO))?;

            code_hash
        } else {
            CodeDB::empty_code_hash()
        };

        self.create.assign(
            region,
            offset,
            call.address,
            caller_nonce.as_u64(),
            Some(U256::from(code_hash.to_fixed_bytes())),
            Some(salt),
        )?;

        // If transfer value is zero, there is no balance update
        let transfer_offset = if value.is_zero() { 2 } else { 0 };
        self.is_success.assign(
            region,
            offset,
            Value::known(if is_precheck_ok == 0 || is_address_collision {
                F::ZERO
            } else if init_code_length.as_usize() == 0 {
                F::ONE
            } else {
                block
                    .get_rws(step, 18 + rw_offset + copy_rw_increase - transfer_offset)
                    .call_context_value()
                    .to_scalar()
                    .unwrap()
            }),
        )?;

        self.is_insufficient_balance
            .assign(region, offset, caller_balance, value)?;
        self.is_depth_in_range
            .assign(region, offset, F::from(call.depth as u64), F::from(1025))?;
        self.is_nonce_in_range.assign(
            region,
            offset,
            F::from(caller_nonce.as_u64()),
            F::from(u64::MAX),
        )?;

        Ok(())
    }
}

