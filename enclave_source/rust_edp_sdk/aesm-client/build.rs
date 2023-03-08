/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate protoc_rust;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo should set OUT_DIR"));

    protoc_rust::run(protoc_rust::Args {
        out_dir: out_dir.to_str().expect("OUT_DIR must be valid UTF-8"),
        input: &["src/aesm_proto.proto"],
        includes: &[],
        customize: Default::default(),
    })
    .expect("protoc");

    // Because of https://github.com/rust-lang/rfcs/issues/752, we can't `include!` the generated
    // protobufs directly. Instead, we generate a second generated file that can be `include!`-ed.
    // This trick borrowed from rust-mbedtls.

    let mod_aesm_proto = out_dir.join("mod_aesm_proto.rs");
    File::create(&mod_aesm_proto)
        // FIXME: get rid of `allow(bare_trait_objects)` by updateing protoc-rust
        .and_then(|mut f| f.write_all(b"#[allow(bare_trait_objects)] mod aesm_proto;\n"))
        .expect("mod_aesm_proto.rs I/O error");
}
