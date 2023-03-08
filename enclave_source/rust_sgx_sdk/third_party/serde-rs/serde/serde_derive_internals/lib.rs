#![doc(html_root_url = "https://docs.rs/serde_derive_internals/0.24.1")]
#![cfg_attr(feature = "cargo-clippy", allow(renamed_and_removed_lints))]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(
        cyclomatic_complexity,
        redundant_field_names,
        trivially_copy_pass_by_ref
    )
)]

#[macro_use]
extern crate syn;

extern crate proc_macro2;
extern crate quote;

#[path = "src/mod.rs"]
mod internals;

pub use internals::*;
