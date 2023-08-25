use super::*;
use serde::{Deserialize, Serialize};

/// The types of proofs in the MPT table
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum MPTProofType {
    /// Disabled
    Disabled,
    /// Nonce updated
    NonceChanged = AccountFieldTag::Nonce as isize,
    /// Balance updated
    BalanceChanged = AccountFieldTag::Balance as isize,
    /// Code hash updated
    CodeHashChanged = AccountFieldTag::CodeHash as isize,
    /// Account destroyed
    AccountDestructed,
    /// Account does not exist
    AccountDoesNotExist,
    /// Storage updated
    StorageChanged,
    /// Storage does not exist
    StorageDoesNotExist,
}
impl_expr!(MPTProofType);

impl From<AccountFieldTag> for MPTProofType {
    fn from(tag: AccountFieldTag) -> Self {
        match tag {
            AccountFieldTag::Nonce => Self::NonceChanged,
            AccountFieldTag::Balance => Self::BalanceChanged,
            AccountFieldTag::CodeHash => Self::CodeHashChanged,
            AccountFieldTag::NonExisting => Self::AccountDoesNotExist,
        }
    }
}

/// The MptTable shared between MPT Circuit and State Circuit
#[derive(Clone, Copy, Debug)]
pub struct MptTable {
    /// Account address
    pub address: Column<Advice>,
    /// Storage address
    pub storage_key: word::Word<Column<Advice>>,
    /// Proof type
    pub proof_type: Column<Advice>,
    /// New MPT root
    pub new_root: word::Word<Column<Advice>>,
    /// Previous MPT root
    pub old_root: word::Word<Column<Advice>>,
    /// New value
    pub new_value: word::Word<Column<Advice>>,
    /// Old value
    pub old_value: word::Word<Column<Advice>>,
}

impl<F: Field> LookupTable<F> for MptTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.address,
            self.storage_key.lo(),
            self.storage_key.hi(),
            self.proof_type,
            self.new_root.lo(),
            self.new_root.hi(),
            self.old_root.lo(),
            self.old_root.hi(),
            self.new_value.lo(),
            self.new_value.hi(),
            self.old_value.lo(),
            self.old_value.hi(),
        ]
        .into_iter()
        .map(|col| col.into())
        .collect::<Vec<Column<Any>>>()
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("address"),
            String::from("storage_key_lo"),
            String::from("storage_key_hi"),
            String::from("proof_type"),
            String::from("new_root_lo"),
            String::from("new_root_hi"),
            String::from("old_root_lo"),
            String::from("old_root_hi"),
            String::from("new_value_lo"),
            String::from("new_value_hi"),
            String::from("old_value_lo"),
            String::from("old_value_hi"),
        ]
    }
}
