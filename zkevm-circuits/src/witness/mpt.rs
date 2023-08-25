use crate::{
    evm_circuit::witness::Rw,
    table::{AccountFieldTag},
    util::word,
};
use eth_types::{Address, Word};
use itertools::Itertools;
use std::collections::BTreeMap;

/// An MPT update whose validity is proved by the MptCircuit
#[derive(Debug, Clone, Copy)]
pub struct MptUpdate {
    old_value: Word,
    new_value: Word,
}

/// All the MPT updates in the MptCircuit, accessible by their key
#[derive(Default, Clone, Debug)]
pub struct MptUpdates {
    updates: BTreeMap<Key, MptUpdate>,
}

/// The field element encoding of an MPT update, which is used by the MptTable
#[derive(Default, Clone, Copy, Debug)]
pub struct MptUpdateRow<F: Clone> {
    pub(crate) address: F,
    pub(crate) storage_key: word::Word<F>,
    pub(crate) proof_type: F,
    pub(crate) new_root: word::Word<F>,
    pub(crate) old_root: word::Word<F>,
    pub(crate) new_value: word::Word<F>,
    pub(crate) old_value: word::Word<F>,
}

impl MptUpdates {
    pub(crate) fn get(&self, row: &Rw) -> Option<MptUpdate> {
        key(row).map(|key| *self.updates.get(&key).expect("missing key in mpt updates"))
    }

    pub(crate) fn mock_from(rows: &[Rw]) -> Self {
        let map: BTreeMap<_, _> = rows
            .iter()
            .group_by(|row| key(row))
            .into_iter()
            .filter_map(|(key, rows)| key.map(|key| (key, rows)))
            .enumerate()
            .map(|(_i, (key, mut rows))| {
                let first = rows.next().unwrap();
                let last = rows.last().unwrap_or(first);
                let key_exists = key;
                (
                    key_exists,
                    MptUpdate {
                        old_value: value_prev(first),
                        new_value: value(last),
                    },
                )
            })
            .collect();
        MptUpdates {
            updates: map,
        }
    }
}

impl MptUpdate {
    pub(crate) fn value_assignments(&self) -> (Word, Word) {
        (self.new_value, self.old_value)
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug, Copy, PartialOrd, Ord)]
enum Key {
    Account {
        address: Address,
        field_tag: AccountFieldTag,
    },
    AccountStorage {
        tx_id: usize,
        address: Address,
        storage_key: Word,
        exists: bool,
    },
}

impl<F: Clone> MptUpdateRow<F> {
    /// The individual values of the row, in the column order used by the
    /// MptTable
    pub fn values(&self) -> [F; 12] {
        [
            self.address.clone(),
            self.storage_key.lo(),
            self.storage_key.hi(),
            self.proof_type.clone(),
            self.new_root.lo(),
            self.new_root.hi(),
            self.old_root.lo(),
            self.old_root.hi(),
            self.new_value.lo(),
            self.new_value.hi(),
            self.old_value.lo(),
            self.old_value.hi(),
        ]
    }
}

fn key(row: &Rw) -> Option<Key> {
    match row {
        Rw::Account {
            account_address,
            field_tag,
            ..
        } => Some(Key::Account {
            address: *account_address,
            field_tag: *field_tag,
        }),
        Rw::AccountStorage {
            tx_id,
            account_address,
            storage_key,
            ..
        } => Some(Key::AccountStorage {
            tx_id: *tx_id,
            address: *account_address,
            storage_key: *storage_key,
            exists: true,
        }),
        _ => None,
    }
}

fn value(row: &Rw) -> Word {
    match row {
        Rw::Account { value, .. } => *value,
        Rw::AccountStorage { value, .. } => *value,
        _ => unreachable!(),
    }
}

fn value_prev(row: &Rw) -> Word {
    match row {
        Rw::Account { value_prev, .. } => *value_prev,
        Rw::AccountStorage { value_prev, .. } => *value_prev,
        _ => unreachable!(),
    }
}
