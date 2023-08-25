#![deny(unused_crate_dependencies)]

//! # zk_evm

// We should try not to use incomplete_features unless it is really really needed and cannot be
// avoided like `adt_const_params` used by DummyGadget
#![allow(incomplete_features)]
// Needed by DummyGadget in evm circuit
#![feature(adt_const_params)]
// Required for adding reasons in allow(dead_code)
#![feature(lint_reasons)]
// Needed by some builder patterns in testing modules.
#![cfg_attr(docsrs, feature(doc_cfg))]
// We want to have UPPERCASE idents sometimes.
#![allow(clippy::upper_case_acronyms)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::debug_assert_with_mut_call)]

#[allow(dead_code, reason = "under active development")]
pub(crate) mod circuit_tools;
pub(crate) mod copy_circuit;
pub(crate) mod evm_circuit;
pub(crate) mod exp_circuit;
pub(crate) mod keccak_circuit;
pub(crate) mod table;

pub(crate) mod util;
pub(crate) mod witness;

pub(crate) use gadgets::impl_expr;
