use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{IsZeroGadget, LtGadget},
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryCopierGasGadget,
                MemoryExpansionGadget,
            },
            select, AccountAddress, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{
        word::{Word, WordCell, WordExpr},
        Expr,
    },
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field, ToAddress, U256,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::CALLDATACOPY`], [`OpcodeId::CODECOPY`],
/// [`OpcodeId::EXTCODECOPY`] and [`OpcodeId::RETURNDATACOPY`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGMemoryCopyGadget<F> {
    opcode: Cell<F>,
    /// Check if `EXTCODECOPY` external address is warm
    is_warm: Cell<F>,
    tx_id: Cell<F>,
    /// Extra stack pop for `EXTCODECOPY`
    external_address: AccountAddress<F>,
    /// Source offset
    src_offset: WordCell<F>,
    /// Destination offset and size to copy
    dst_memory_addr: MemoryAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    is_extcodecopy: IsZeroGadget<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGMemoryCopyGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasMemoryCopy";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasMemoryCopy;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_in_set(
            "ErrorOutOfGasMemoryCopy opcode must be CALLDATACOPY, CODECOPY, EXTCODECOPY or RETURNDATACOPY",
            opcode.expr(),
            vec![
                OpcodeId::CALLDATACOPY.expr(),
                OpcodeId::CODECOPY.expr(),
                OpcodeId::EXTCODECOPY.expr(),
                OpcodeId::RETURNDATACOPY.expr(),
            ],
        );

        let dst_offset = cb.query_word_unchecked();
        let src_offset = cb.query_word_unchecked();
        let copy_size = cb.query_memory_address();
        let external_address = cb.query_account_address();
        let is_warm = cb.query_bool();
        let tx_id = cb.query_cell();

        let is_extcodecopy =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::EXTCODECOPY.expr());

        cb.condition(is_extcodecopy.expr(), |cb| {
            cb.call_context_lookup_read(
                None,
                CallContextFieldTag::TxId,
                Word::from_lo_unchecked(tx_id.expr()),
            );

            // Check if EXTCODECOPY external address is warm.
            cb.account_access_list_read(tx_id.expr(), external_address.to_word(), is_warm.expr());

            // EXTCODECOPY has an extra stack pop for external address.
            cb.stack_pop(external_address.to_word());
        });

        cb.stack_pop(dst_offset.to_word());
        cb.stack_pop(src_offset.to_word());
        cb.stack_pop(copy_size.to_word());

        let dst_memory_addr = MemoryAddressGadget::construct(cb, dst_offset, copy_size);
        let memory_expansion = MemoryExpansionGadget::construct(cb, [dst_memory_addr.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            dst_memory_addr.length(),
            memory_expansion.gas_cost(),
        );

        let constant_gas_cost = select::expr(
            is_extcodecopy.expr(),
            // According to EIP-2929, EXTCODECOPY constant gas cost is different for cold and warm
            // accounts.
            select::expr(
                is_warm.expr(),
                GasCost::WARM_ACCESS.expr(),
                GasCost::COLD_ACCOUNT_ACCESS.expr(),
            ),
            // Constant gas cost is same for CALLDATACOPY, CODECOPY and RETURNDATACOPY.
            OpcodeId::CALLDATACOPY.constant_gas_cost().expr(),
        );

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            constant_gas_cost + memory_copier_gas.gas_cost(),
        );

        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(
            cb,
            opcode.expr(),
            // EXTCODECOPY has extra 1 call context lookup (tx_id), 1 account access list
            // read (is_warm), and 1 stack pop (external_address).
            5.expr() + 3.expr() * is_extcodecopy.expr(),
        );

        Self {
            opcode,
            is_warm,
            tx_id,
            external_address,
            src_offset,
            dst_memory_addr,
            memory_expansion,
            memory_copier_gas,
            insufficient_gas,
            is_extcodecopy,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode().unwrap();
        let is_extcodecopy = opcode == OpcodeId::EXTCODECOPY;

        log::debug!(
            "ErrorOutOfGasMemoryCopy: opcode = {}, gas_left = {}, gas_cost = {}",
            opcode,
            step.gas_left,
            step.gas_cost,
        );

        let (is_warm, external_address) = if is_extcodecopy {
            (
                block.get_rws(step, 1).tx_access_list_value_pair().0,
                block.get_rws(step, 2).stack_value(),
            )
        } else {
            (false, U256::zero())
        };

        let rw_offset = if is_extcodecopy { 3 } else { 0 };
        let [dst_offset, src_offset, copy_size] = [rw_offset, rw_offset + 1, rw_offset + 2]
            .map(|index| block.get_rws(step, index).stack_value());

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.is_warm
            .assign(region, offset, Value::known(F::from(u64::from(is_warm))))?;
        self.tx_id
            .assign(region, offset, Value::known(F::from(transaction.id)))?;
        self.external_address
            .assign_h160(region, offset, external_address.to_address())?;
        self.src_offset.assign_u256(region, offset, src_offset)?;
        let memory_addr = self
            .dst_memory_addr
            .assign(region, offset, dst_offset, copy_size)?;
        let (_, memory_expansion_cost) =
            self.memory_expansion
                .assign(region, offset, step.memory_word_size(), [memory_addr])?;
        let memory_copier_gas = self.memory_copier_gas.assign(
            region,
            offset,
            copy_size.as_u64(),
            memory_expansion_cost,
        )?;
        let constant_gas_cost = if is_extcodecopy {
            if is_warm {
                GasCost::WARM_ACCESS
            } else {
                GasCost::COLD_ACCOUNT_ACCESS
            }
        } else {
            GasCost::FASTEST
        };
        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(constant_gas_cost + memory_copier_gas)),
        )?;
        self.is_extcodecopy.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::EXTCODECOPY.as_u64()),
        )?;
        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            // EXTCODECOPY has extra 1 call context lookup (tx_id), 1 account access list
            // read (is_warm), and 1 stack pop (external_address).
            5 + if is_extcodecopy { 3 } else { 0 },
        )?;

        Ok(())
    }
}
