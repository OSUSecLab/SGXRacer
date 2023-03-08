// These just test that serde_derive is able to produce code that compiles
// successfully when there are a variety of generics and non-(de)serializable
// types involved.

#![deny(warnings)]
#![cfg_attr(feature = "unstable", feature(non_ascii_idents))]
#![allow(clippy::trivially_copy_pass_by_ref)]

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::borrow::Cow;
use std::marker::PhantomData;
use std::option::Option as StdOption;
use std::result::Result as StdResult;

// Try to trip up the generated code if it fails to use fully qualified paths.
#[allow(dead_code)]
struct Result;
#[allow(dead_code)]
struct Ok;
#[allow(dead_code)]
struct Err;
#[allow(dead_code)]
struct Option;
#[allow(dead_code)]
struct Some;
#[allow(dead_code)]
struct None;

//////////////////////////////////////////////////////////////////////////

#[test]
fn test_gen() {
    #[derive(Serialize, Deserialize)]
    struct With<T> {
        t: T,
        #[serde(serialize_with = "ser_x", deserialize_with = "de_x")]
        x: X,
    }
    assert::<With<i32>>();

    #[derive(Serialize, Deserialize)]
    struct WithTogether<T> {
        t: T,
        #[serde(with = "both_x")]
        x: X,
    }
    assert::<WithTogether<i32>>();

    #[derive(Serialize, Deserialize)]
    struct WithRef<'a, T: 'a> {
        #[serde(skip_deserializing)]
        t: StdOption<&'a T>,
        #[serde(serialize_with = "ser_x", deserialize_with = "de_x")]
        x: X,
    }
    assert::<WithRef<i32>>();

    #[derive(Serialize, Deserialize)]
    struct PhantomX {
        x: PhantomData<X>,
    }
    assert::<PhantomX>();

    #[derive(Serialize, Deserialize)]
    struct PhantomT<T> {
        t: PhantomData<T>,
    }
    assert::<PhantomT<X>>();

    #[derive(Serialize, Deserialize)]
    struct NoBounds<T> {
        t: T,
        option: StdOption<T>,
        boxed: Box<T>,
        option_boxed: StdOption<Box<T>>,
    }
    assert::<NoBounds<i32>>();

    #[derive(Serialize, Deserialize)]
    enum EnumWith<T> {
        Unit,
        Newtype(#[serde(serialize_with = "ser_x", deserialize_with = "de_x")] X),
        Tuple(
            T,
            #[serde(serialize_with = "ser_x", deserialize_with = "de_x")] X,
        ),
        Struct {
            t: T,
            #[serde(serialize_with = "ser_x", deserialize_with = "de_x")]
            x: X,
        },
    }
    assert::<EnumWith<i32>>();

    #[derive(Serialize)]
    struct MultipleRef<'a, 'b, 'c, T>
    where
        T: 'c,
        'c: 'b,
        'b: 'a,
    {
        t: T,
        rrrt: &'a &'b &'c T,
    }
    assert_ser::<MultipleRef<i32>>();

    #[derive(Serialize, Deserialize)]
    struct Newtype(#[serde(serialize_with = "ser_x", deserialize_with = "de_x")] X);
    assert::<Newtype>();

    #[derive(Serialize, Deserialize)]
    struct Tuple<T>(
        T,
        #[serde(serialize_with = "ser_x", deserialize_with = "de_x")] X,
    );
    assert::<Tuple<i32>>();

    #[derive(Serialize, Deserialize)]
    enum TreeNode<D> {
        Split {
            left: Box<TreeNode<D>>,
            right: Box<TreeNode<D>>,
        },
        Leaf {
            data: D,
        },
    }
    assert::<TreeNode<i32>>();

    #[derive(Serialize, Deserialize)]
    struct ListNode<D> {
        data: D,
        next: Box<ListNode<D>>,
    }
    assert::<ListNode<i32>>();

    #[derive(Serialize, Deserialize)]
    struct RecursiveA {
        b: Box<RecursiveB>,
    }
    assert::<RecursiveA>();

    #[derive(Serialize, Deserialize)]
    enum RecursiveB {
        A(RecursiveA),
    }
    assert::<RecursiveB>();

    #[derive(Serialize, Deserialize)]
    struct RecursiveGenericA<T> {
        t: T,
        b: Box<RecursiveGenericB<T>>,
    }
    assert::<RecursiveGenericA<i32>>();

    #[derive(Serialize, Deserialize)]
    enum RecursiveGenericB<T> {
        T(T),
        A(RecursiveGenericA<T>),
    }
    assert::<RecursiveGenericB<i32>>();

    #[derive(Serialize)]
    struct OptionStatic<'a> {
        a: StdOption<&'a str>,
        b: StdOption<&'static str>,
    }
    assert_ser::<OptionStatic>();

    #[derive(Serialize, Deserialize)]
    #[serde(bound = "D: SerializeWith + DeserializeWith")]
    struct WithTraits1<D, E> {
        #[serde(
            serialize_with = "SerializeWith::serialize_with",
            deserialize_with = "DeserializeWith::deserialize_with"
        )]
        d: D,
        #[serde(
            serialize_with = "SerializeWith::serialize_with",
            deserialize_with = "DeserializeWith::deserialize_with",
            bound = "E: SerializeWith + DeserializeWith"
        )]
        e: E,
    }
    assert::<WithTraits1<X, X>>();

    #[derive(Serialize, Deserialize)]
    #[serde(bound(serialize = "D: SerializeWith", deserialize = "D: DeserializeWith"))]
    struct WithTraits2<D, E> {
        #[serde(
            serialize_with = "SerializeWith::serialize_with",
            deserialize_with = "DeserializeWith::deserialize_with"
        )]
        d: D,
        #[serde(
            serialize_with = "SerializeWith::serialize_with",
            bound(serialize = "E: SerializeWith")
        )]
        #[serde(
            deserialize_with = "DeserializeWith::deserialize_with",
            bound(deserialize = "E: DeserializeWith")
        )]
        e: E,
    }
    assert::<WithTraits2<X, X>>();

    #[derive(Serialize, Deserialize)]
    #[serde(bound = "D: SerializeWith + DeserializeWith")]
    enum VariantWithTraits1<D, E> {
        #[serde(
            serialize_with = "SerializeWith::serialize_with",
            deserialize_with = "DeserializeWith::deserialize_with"
        )]
        D(D),
        #[serde(
            serialize_with = "SerializeWith::serialize_with",
            deserialize_with = "DeserializeWith::deserialize_with",
            bound = "E: SerializeWith + DeserializeWith"
        )]
        E(E),
    }
    assert::<VariantWithTraits1<X, X>>();

    #[derive(Serialize, Deserialize)]
    #[serde(bound(serialize = "D: SerializeWith", deserialize = "D: DeserializeWith"))]
    enum VariantWithTraits2<D, E> {
        #[serde(
            serialize_with = "SerializeWith::serialize_with",
            deserialize_with = "DeserializeWith::deserialize_with"
        )]
        D(D),
        #[serde(
            serialize_with = "SerializeWith::serialize_with",
            bound(serialize = "E: SerializeWith")
        )]
        #[serde(
            deserialize_with = "DeserializeWith::deserialize_with",
            bound(deserialize = "E: DeserializeWith")
        )]
        E(E),
    }
    assert::<VariantWithTraits2<X, X>>();

    #[derive(Serialize, Deserialize)]
    struct CowStr<'a>(Cow<'a, str>);
    assert::<CowStr>();

    #[derive(Serialize, Deserialize)]
    #[serde(bound(deserialize = "T::Owned: DeserializeOwned"))]
    struct CowT<'a, T: ?Sized + 'a + ToOwned>(Cow<'a, T>);
    assert::<CowT<str>>();

    #[derive(Serialize, Deserialize)]
    struct EmptyStruct {}
    assert::<EmptyStruct>();

    #[derive(Serialize, Deserialize)]
    enum EmptyEnumVariant {
        EmptyStruct {},
    }
    assert::<EmptyEnumVariant>();

    #[cfg(feature = "unstable")]
    #[derive(Serialize, Deserialize)]
    struct NonAsciiIdents {
        σ: f64,
    }

    #[derive(Serialize, Deserialize)]
    struct EmptyBraced {}

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EmptyBracedDenyUnknown {}

    #[derive(Serialize, Deserialize)]
    struct BracedSkipAll {
        #[serde(skip_deserializing)]
        f: u8,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BracedSkipAllDenyUnknown {
        #[serde(skip_deserializing)]
        f: u8,
    }

    #[derive(Serialize, Deserialize)]
    struct EmptyTuple();

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EmptyTupleDenyUnknown();

    #[derive(Serialize, Deserialize)]
    struct TupleSkipAll(#[serde(skip_deserializing)] u8);

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TupleSkipAllDenyUnknown(#[serde(skip_deserializing)] u8);

    #[derive(Serialize, Deserialize)]
    enum EmptyEnum {}

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    enum EmptyEnumDenyUnknown {}

    #[derive(Serialize, Deserialize)]
    enum EnumSkipAll {
        #[serde(skip_deserializing)]
        #[allow(dead_code)]
        Variant,
    }

    #[derive(Serialize, Deserialize)]
    enum EmptyVariants {
        Braced {},
        Tuple(),
        BracedSkip {
            #[serde(skip_deserializing)]
            f: u8,
        },
        TupleSkip(#[serde(skip_deserializing)] u8),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    enum EmptyVariantsDenyUnknown {
        Braced {},
        Tuple(),
        BracedSkip {
            #[serde(skip_deserializing)]
            f: u8,
        },
        TupleSkip(#[serde(skip_deserializing)] u8),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct UnitDenyUnknown;

    #[derive(Serialize, Deserialize)]
    struct EmptyArray {
        empty: [X; 0],
    }

    enum Or<A, B> {
        A(A),
        B(B),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(untagged, remote = "Or")]
    enum OrDef<A, B> {
        A(A),
        B(B),
    }

    struct Str<'a>(&'a str);

    #[derive(Serialize, Deserialize)]
    #[serde(remote = "Str")]
    struct StrDef<'a>(&'a str);

    #[derive(Serialize, Deserialize)]
    struct Remote<'a> {
        #[serde(with = "OrDef")]
        or: Or<u8, bool>,
        #[serde(borrow, with = "StrDef")]
        s: Str<'a>,
    }

    #[derive(Serialize, Deserialize)]
    enum BorrowVariant<'a> {
        #[serde(borrow, with = "StrDef")]
        S(Str<'a>),
    }

    mod vis {
        use serde::{Deserialize, Serialize};

        pub struct S;

        #[derive(Serialize, Deserialize)]
        #[serde(remote = "S")]
        pub struct SDef;
    }

    // This would not work if SDef::serialize / deserialize are private.
    #[derive(Serialize, Deserialize)]
    struct RemoteVisibility {
        #[serde(with = "vis::SDef")]
        s: vis::S,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(remote = "Self")]
    struct RemoteSelf;

    #[derive(Serialize, Deserialize)]
    enum ExternallyTaggedVariantWith {
        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        #[allow(dead_code)]
        Newtype(X),

        #[serde(serialize_with = "serialize_some_other_variant")]
        #[serde(deserialize_with = "deserialize_some_other_variant")]
        #[allow(dead_code)]
        Tuple(String, u8),

        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        #[allow(dead_code)]
        Struct1 { x: X },

        #[serde(serialize_with = "serialize_some_other_variant")]
        #[serde(deserialize_with = "deserialize_some_other_variant")]
        #[allow(dead_code)]
        Struct { f1: String, f2: u8 },

        #[serde(serialize_with = "serialize_some_unit_variant")]
        #[serde(deserialize_with = "deserialize_some_unit_variant")]
        #[allow(dead_code)]
        Unit,
    }
    assert_ser::<ExternallyTaggedVariantWith>();

    #[derive(Serialize, Deserialize)]
    #[serde(tag = "t")]
    enum InternallyTaggedVariantWith {
        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        #[allow(dead_code)]
        Newtype(X),

        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        #[allow(dead_code)]
        Struct1 { x: X },

        #[serde(serialize_with = "serialize_some_other_variant")]
        #[serde(deserialize_with = "deserialize_some_other_variant")]
        #[allow(dead_code)]
        Struct { f1: String, f2: u8 },

        #[serde(serialize_with = "serialize_some_unit_variant")]
        #[serde(deserialize_with = "deserialize_some_unit_variant")]
        #[allow(dead_code)]
        Unit,
    }
    assert_ser::<InternallyTaggedVariantWith>();

    #[derive(Serialize, Deserialize)]
    #[serde(tag = "t", content = "c")]
    enum AdjacentlyTaggedVariantWith {
        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        #[allow(dead_code)]
        Newtype(X),

        #[serde(serialize_with = "serialize_some_other_variant")]
        #[serde(deserialize_with = "deserialize_some_other_variant")]
        #[allow(dead_code)]
        Tuple(String, u8),

        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        #[allow(dead_code)]
        Struct1 { x: X },

        #[serde(serialize_with = "serialize_some_other_variant")]
        #[serde(deserialize_with = "deserialize_some_other_variant")]
        #[allow(dead_code)]
        Struct { f1: String, f2: u8 },

        #[serde(serialize_with = "serialize_some_unit_variant")]
        #[serde(deserialize_with = "deserialize_some_unit_variant")]
        #[allow(dead_code)]
        Unit,
    }
    assert_ser::<AdjacentlyTaggedVariantWith>();

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum UntaggedVariantWith {
        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        #[allow(dead_code)]
        Newtype(X),

        #[serde(serialize_with = "serialize_some_other_variant")]
        #[serde(deserialize_with = "deserialize_some_other_variant")]
        #[allow(dead_code)]
        Tuple(String, u8),

        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        #[allow(dead_code)]
        Struct1 { x: X },

        #[serde(serialize_with = "serialize_some_other_variant")]
        #[serde(deserialize_with = "deserialize_some_other_variant")]
        #[allow(dead_code)]
        Struct { f1: String, f2: u8 },

        #[serde(serialize_with = "serialize_some_unit_variant")]
        #[serde(deserialize_with = "deserialize_some_unit_variant")]
        #[allow(dead_code)]
        Unit,
    }
    assert_ser::<UntaggedVariantWith>();

    #[derive(Serialize, Deserialize)]
    struct FlattenWith {
        #[serde(flatten, serialize_with = "ser_x", deserialize_with = "de_x")]
        x: X,
    }
    assert::<FlattenWith>();

    #[derive(Serialize, Deserialize)]
    struct StaticStrStruct<'a> {
        a: &'a str,
        b: &'static str,
    }

    #[derive(Serialize, Deserialize)]
    struct StaticStrTupleStruct<'a>(&'a str, &'static str);

    #[derive(Serialize, Deserialize)]
    struct StaticStrNewtypeStruct(&'static str);

    #[derive(Serialize, Deserialize)]
    enum StaticStrEnum<'a> {
        Struct { a: &'a str, b: &'static str },
        Tuple(&'a str, &'static str),
        Newtype(&'static str),
    }

    #[derive(Serialize, Deserialize)]
    struct SkippedStaticStr {
        #[serde(skip_deserializing)]
        skipped: &'static str,
        other: isize,
    }
    assert::<SkippedStaticStr>();

    macro_rules! T {
        () => {
            ()
        };
    }

    #[derive(Serialize, Deserialize)]
    struct TypeMacro<T> {
        mac: T!(),
        marker: PhantomData<T>,
    }
    assert::<TypeMacro<X>>();

    #[derive(Serialize)]
    struct BigArray {
        #[serde(serialize_with = "<[_]>::serialize")]
        array: [u8; 256],
    }
    assert_ser::<BigArray>();

    trait AssocSerde {
        type Assoc;
    }

    struct NoSerdeImpl;
    impl AssocSerde for NoSerdeImpl {
        type Assoc = u32;
    }

    #[derive(Serialize, Deserialize)]
    struct AssocDerive<T: AssocSerde> {
        assoc: T::Assoc,
    }

    assert::<AssocDerive<NoSerdeImpl>>();

    #[derive(Serialize, Deserialize)]
    struct AssocDeriveMulti<S, T: AssocSerde> {
        s: S,
        assoc: T::Assoc,
    }

    assert::<AssocDeriveMulti<i32, NoSerdeImpl>>();

    #[derive(Serialize)]
    #[serde(tag = "t", content = "c")]
    enum EmptyAdjacentlyTagged {
        #[allow(dead_code)]
        Struct {},
        #[allow(dead_code)]
        Tuple(),
    }

    assert_ser::<EmptyAdjacentlyTagged>();

    mod restricted {
        mod inner {
            use serde::{Deserialize, Serialize};

            #[derive(Serialize, Deserialize)]
            struct Restricted {
                pub(super) a: usize,
                pub(in super::inner) b: usize,
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(tag = "t", content = "c")]
    enum AdjacentlyTaggedVoid {}

    #[derive(Serialize, Deserialize)]
    enum SkippedVariant<T> {
        #[serde(skip)]
        #[allow(dead_code)]
        T(T),
        Unit,
    }

    assert::<SkippedVariant<X>>();

    #[derive(Deserialize)]
    struct ImpliciltyBorrowedOption<'a> {
        option: std::option::Option<&'a str>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum UntaggedNewtypeVariantWith {
        Newtype(
            #[serde(serialize_with = "ser_x")]
            #[serde(deserialize_with = "de_x")]
            X,
        ),
    }

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct TransparentWith {
        #[serde(serialize_with = "ser_x")]
        #[serde(deserialize_with = "de_x")]
        x: X,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum UntaggedWithBorrow<'a> {
        Single(#[serde(borrow)] RelObject<'a>),
        Many(#[serde(borrow)] Vec<RelObject<'a>>),
    }

    #[derive(Deserialize)]
    struct RelObject<'a> {
        ty: &'a str,
        id: String,
    }
}

//////////////////////////////////////////////////////////////////////////

fn assert<T: Serialize + DeserializeOwned>() {}
fn assert_ser<T: Serialize>() {}

trait SerializeWith {
    fn serialize_with<S: Serializer>(_: &Self, _: S) -> StdResult<S::Ok, S::Error>;
}

trait DeserializeWith: Sized {
    fn deserialize_with<'de, D: Deserializer<'de>>(_: D) -> StdResult<Self, D::Error>;
}

// Implements neither Serialize nor Deserialize
pub struct X;

pub fn ser_x<S: Serializer>(_: &X, _: S) -> StdResult<S::Ok, S::Error> {
    unimplemented!()
}

pub fn de_x<'de, D: Deserializer<'de>>(_: D) -> StdResult<X, D::Error> {
    unimplemented!()
}

mod both_x {
    pub use super::{de_x as deserialize, ser_x as serialize};
}

impl SerializeWith for X {
    fn serialize_with<S: Serializer>(_: &Self, _: S) -> StdResult<S::Ok, S::Error> {
        unimplemented!()
    }
}

impl DeserializeWith for X {
    fn deserialize_with<'de, D: Deserializer<'de>>(_: D) -> StdResult<Self, D::Error> {
        unimplemented!()
    }
}

pub fn serialize_some_unit_variant<S>(_: S) -> StdResult<S::Ok, S::Error>
where
    S: Serializer,
{
    unimplemented!()
}

pub fn deserialize_some_unit_variant<'de, D>(_: D) -> StdResult<(), D::Error>
where
    D: Deserializer<'de>,
{
    unimplemented!()
}

pub fn serialize_some_other_variant<S>(_: &str, _: &u8, _: S) -> StdResult<S::Ok, S::Error>
where
    S: Serializer,
{
    unimplemented!()
}

pub fn deserialize_some_other_variant<'de, D>(_: D) -> StdResult<(String, u8), D::Error>
where
    D: Deserializer<'de>,
{
    unimplemented!()
}

pub fn is_zero(n: &u8) -> bool {
    *n == 0
}
