// DO NOT EDIT THIS FILE. IT WAS AUTOMATICALLY GENERATED BY:
//
//  ucd-generate names tmp/ucd-11.0.0/ --no-aliases --no-hangul --no-ideograph --fst-dir benches/tables/fst
//
// ucd-generate is available on crates.io.

lazy_static! {
  pub static ref NAMES: ::fst::Map =
    ::fst::Map::from(::fst::raw::Fst::from_static_slice(
      include_bytes!("names.fst")).unwrap());
}
