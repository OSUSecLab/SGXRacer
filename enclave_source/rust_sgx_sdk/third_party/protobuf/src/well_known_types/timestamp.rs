// This file is generated by rust-protobuf 1.6.0. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

use std::prelude::v1::*;


use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

#[derive(PartialEq,Clone,Default)]
pub struct Timestamp {
    // message fields
    pub seconds: i64,
    pub nanos: i32,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

impl Timestamp {
    pub fn new() -> Timestamp {
        ::std::default::Default::default()
    }

    // int64 seconds = 1;

    pub fn clear_seconds(&mut self) {
        self.seconds = 0;
    }

    // Param is passed by value, moved
    pub fn set_seconds(&mut self, v: i64) {
        self.seconds = v;
    }

    pub fn get_seconds(&self) -> i64 {
        self.seconds
    }

    // int32 nanos = 2;

    pub fn clear_nanos(&mut self) {
        self.nanos = 0;
    }

    // Param is passed by value, moved
    pub fn set_nanos(&mut self, v: i32) {
        self.nanos = v;
    }

    pub fn get_nanos(&self) -> i32 {
        self.nanos
    }
}

impl ::protobuf::Message for Timestamp {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int64()?;
                    self.seconds = tmp;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.nanos = tmp;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if self.seconds != 0 {
            my_size += ::protobuf::rt::value_size(1, self.seconds, ::protobuf::wire_format::WireTypeVarint);
        }
        if self.nanos != 0 {
            my_size += ::protobuf::rt::value_size(2, self.nanos, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if self.seconds != 0 {
            os.write_int64(1, self.seconds)?;
        }
        if self.nanos != 0 {
            os.write_int32(2, self.nanos)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        Self::descriptor_static()
    }

    fn new() -> Timestamp {
        Timestamp::new()
    }

    fn descriptor_static() -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeInt64>(
                    "seconds",
                    |m: &Timestamp| { &m.seconds },
                    |m: &mut Timestamp| { &mut m.seconds },
                ));
                fields.push(::protobuf::reflect::accessor::make_simple_field_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "nanos",
                    |m: &Timestamp| { &m.nanos },
                    |m: &mut Timestamp| { &mut m.nanos },
                ));
                ::protobuf::reflect::MessageDescriptor::new::<Timestamp>(
                    "Timestamp",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }

    fn default_instance() -> &'static Timestamp {
        static mut instance: ::protobuf::lazy::Lazy<Timestamp> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const Timestamp,
        };
        unsafe {
            instance.get(Timestamp::new)
        }
    }
}

impl ::protobuf::Clear for Timestamp {
    fn clear(&mut self) {
        self.clear_seconds();
        self.clear_nanos();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Timestamp {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x1fgoogle/protobuf/timestamp.proto\x12\x0fgoogle.protobuf\";\n\tTimes\
    tamp\x12\x18\n\x07seconds\x18\x01\x20\x01(\x03R\x07seconds\x12\x14\n\x05\
    nanos\x18\x02\x20\x01(\x05R\x05nanosB~\n\x13com.google.protobufB\x0eTime\
    stampProtoP\x01Z+github.com/golang/protobuf/ptypes/timestamp\xf8\x01\x01\
    \xa2\x02\x03GPB\xaa\x02\x1eGoogle.Protobuf.WellKnownTypesJ\xde$\n\x06\
    \x12\x04\x1e\0k\x01\n\xcc\x0c\n\x01\x0c\x12\x03\x1e\0\x122\xc1\x0c\x20Pr\
    otocol\x20Buffers\x20-\x20Google's\x20data\x20interchange\x20format\n\
    \x20Copyright\x202008\x20Google\x20Inc.\x20\x20All\x20rights\x20reserved\
    .\n\x20https://developers.google.com/protocol-buffers/\n\n\x20Redistribu\
    tion\x20and\x20use\x20in\x20source\x20and\x20binary\x20forms,\x20with\
    \x20or\x20without\n\x20modification,\x20are\x20permitted\x20provided\x20\
    that\x20the\x20following\x20conditions\x20are\n\x20met:\n\n\x20\x20\x20\
    \x20\x20*\x20Redistributions\x20of\x20source\x20code\x20must\x20retain\
    \x20the\x20above\x20copyright\n\x20notice,\x20this\x20list\x20of\x20cond\
    itions\x20and\x20the\x20following\x20disclaimer.\n\x20\x20\x20\x20\x20*\
    \x20Redistributions\x20in\x20binary\x20form\x20must\x20reproduce\x20the\
    \x20above\n\x20copyright\x20notice,\x20this\x20list\x20of\x20conditions\
    \x20and\x20the\x20following\x20disclaimer\n\x20in\x20the\x20documentatio\
    n\x20and/or\x20other\x20materials\x20provided\x20with\x20the\n\x20distri\
    bution.\n\x20\x20\x20\x20\x20*\x20Neither\x20the\x20name\x20of\x20Google\
    \x20Inc.\x20nor\x20the\x20names\x20of\x20its\n\x20contributors\x20may\
    \x20be\x20used\x20to\x20endorse\x20or\x20promote\x20products\x20derived\
    \x20from\n\x20this\x20software\x20without\x20specific\x20prior\x20writte\
    n\x20permission.\n\n\x20THIS\x20SOFTWARE\x20IS\x20PROVIDED\x20BY\x20THE\
    \x20COPYRIGHT\x20HOLDERS\x20AND\x20CONTRIBUTORS\n\x20\"AS\x20IS\"\x20AND\
    \x20ANY\x20EXPRESS\x20OR\x20IMPLIED\x20WARRANTIES,\x20INCLUDING,\x20BUT\
    \x20NOT\n\x20LIMITED\x20TO,\x20THE\x20IMPLIED\x20WARRANTIES\x20OF\x20MER\
    CHANTABILITY\x20AND\x20FITNESS\x20FOR\n\x20A\x20PARTICULAR\x20PURPOSE\
    \x20ARE\x20DISCLAIMED.\x20IN\x20NO\x20EVENT\x20SHALL\x20THE\x20COPYRIGHT\
    \n\x20OWNER\x20OR\x20CONTRIBUTORS\x20BE\x20LIABLE\x20FOR\x20ANY\x20DIREC\
    T,\x20INDIRECT,\x20INCIDENTAL,\n\x20SPECIAL,\x20EXEMPLARY,\x20OR\x20CONS\
    EQUENTIAL\x20DAMAGES\x20(INCLUDING,\x20BUT\x20NOT\n\x20LIMITED\x20TO,\
    \x20PROCUREMENT\x20OF\x20SUBSTITUTE\x20GOODS\x20OR\x20SERVICES;\x20LOSS\
    \x20OF\x20USE,\n\x20DATA,\x20OR\x20PROFITS;\x20OR\x20BUSINESS\x20INTERRU\
    PTION)\x20HOWEVER\x20CAUSED\x20AND\x20ON\x20ANY\n\x20THEORY\x20OF\x20LIA\
    BILITY,\x20WHETHER\x20IN\x20CONTRACT,\x20STRICT\x20LIABILITY,\x20OR\x20T\
    ORT\n\x20(INCLUDING\x20NEGLIGENCE\x20OR\x20OTHERWISE)\x20ARISING\x20IN\
    \x20ANY\x20WAY\x20OUT\x20OF\x20THE\x20USE\n\x20OF\x20THIS\x20SOFTWARE,\
    \x20EVEN\x20IF\x20ADVISED\x20OF\x20THE\x20POSSIBILITY\x20OF\x20SUCH\x20D\
    AMAGE.\n\n\x08\n\x01\x02\x12\x03\x20\x08\x17\n\x08\n\x01\x08\x12\x03\"\0\
    ;\n\x0b\n\x04\x08\xe7\x07\0\x12\x03\"\0;\n\x0c\n\x05\x08\xe7\x07\0\x02\
    \x12\x03\"\x07\x17\n\r\n\x06\x08\xe7\x07\0\x02\0\x12\x03\"\x07\x17\n\x0e\
    \n\x07\x08\xe7\x07\0\x02\0\x01\x12\x03\"\x07\x17\n\x0c\n\x05\x08\xe7\x07\
    \0\x07\x12\x03\"\x1a:\n\x08\n\x01\x08\x12\x03#\0\x1f\n\x0b\n\x04\x08\xe7\
    \x07\x01\x12\x03#\0\x1f\n\x0c\n\x05\x08\xe7\x07\x01\x02\x12\x03#\x07\x17\
    \n\r\n\x06\x08\xe7\x07\x01\x02\0\x12\x03#\x07\x17\n\x0e\n\x07\x08\xe7\
    \x07\x01\x02\0\x01\x12\x03#\x07\x17\n\x0c\n\x05\x08\xe7\x07\x01\x03\x12\
    \x03#\x1a\x1e\n\x08\n\x01\x08\x12\x03$\0B\n\x0b\n\x04\x08\xe7\x07\x02\
    \x12\x03$\0B\n\x0c\n\x05\x08\xe7\x07\x02\x02\x12\x03$\x07\x11\n\r\n\x06\
    \x08\xe7\x07\x02\x02\0\x12\x03$\x07\x11\n\x0e\n\x07\x08\xe7\x07\x02\x02\
    \0\x01\x12\x03$\x07\x11\n\x0c\n\x05\x08\xe7\x07\x02\x07\x12\x03$\x14A\n\
    \x08\n\x01\x08\x12\x03%\0,\n\x0b\n\x04\x08\xe7\x07\x03\x12\x03%\0,\n\x0c\
    \n\x05\x08\xe7\x07\x03\x02\x12\x03%\x07\x13\n\r\n\x06\x08\xe7\x07\x03\
    \x02\0\x12\x03%\x07\x13\n\x0e\n\x07\x08\xe7\x07\x03\x02\0\x01\x12\x03%\
    \x07\x13\n\x0c\n\x05\x08\xe7\x07\x03\x07\x12\x03%\x16+\n\x08\n\x01\x08\
    \x12\x03&\0/\n\x0b\n\x04\x08\xe7\x07\x04\x12\x03&\0/\n\x0c\n\x05\x08\xe7\
    \x07\x04\x02\x12\x03&\x07\x1b\n\r\n\x06\x08\xe7\x07\x04\x02\0\x12\x03&\
    \x07\x1b\n\x0e\n\x07\x08\xe7\x07\x04\x02\0\x01\x12\x03&\x07\x1b\n\x0c\n\
    \x05\x08\xe7\x07\x04\x07\x12\x03&\x1e.\n\x08\n\x01\x08\x12\x03'\0\"\n\
    \x0b\n\x04\x08\xe7\x07\x05\x12\x03'\0\"\n\x0c\n\x05\x08\xe7\x07\x05\x02\
    \x12\x03'\x07\x1a\n\r\n\x06\x08\xe7\x07\x05\x02\0\x12\x03'\x07\x1a\n\x0e\
    \n\x07\x08\xe7\x07\x05\x02\0\x01\x12\x03'\x07\x1a\n\x0c\n\x05\x08\xe7\
    \x07\x05\x03\x12\x03'\x1d!\n\x08\n\x01\x08\x12\x03(\0!\n\x0b\n\x04\x08\
    \xe7\x07\x06\x12\x03(\0!\n\x0c\n\x05\x08\xe7\x07\x06\x02\x12\x03(\x07\
    \x18\n\r\n\x06\x08\xe7\x07\x06\x02\0\x12\x03(\x07\x18\n\x0e\n\x07\x08\
    \xe7\x07\x06\x02\0\x01\x12\x03(\x07\x18\n\x0c\n\x05\x08\xe7\x07\x06\x07\
    \x12\x03(\x1b\x20\n\xb8\x0f\n\x02\x04\0\x12\x04_\0k\x01\x1a\xab\x0f\x20A\
    \x20Timestamp\x20represents\x20a\x20point\x20in\x20time\x20independent\
    \x20of\x20any\x20time\x20zone\n\x20or\x20calendar,\x20represented\x20as\
    \x20seconds\x20and\x20fractions\x20of\x20seconds\x20at\n\x20nanosecond\
    \x20resolution\x20in\x20UTC\x20Epoch\x20time.\x20It\x20is\x20encoded\x20\
    using\x20the\n\x20Proleptic\x20Gregorian\x20Calendar\x20which\x20extends\
    \x20the\x20Gregorian\x20calendar\n\x20backwards\x20to\x20year\x20one.\
    \x20It\x20is\x20encoded\x20assuming\x20all\x20minutes\x20are\x2060\n\x20\
    seconds\x20long,\x20i.e.\x20leap\x20seconds\x20are\x20\"smeared\"\x20so\
    \x20that\x20no\x20leap\x20second\n\x20table\x20is\x20needed\x20for\x20in\
    terpretation.\x20Range\x20is\x20from\n\x200001-01-01T00:00:00Z\x20to\x20\
    9999-12-31T23:59:59.999999999Z.\n\x20By\x20restricting\x20to\x20that\x20\
    range,\x20we\x20ensure\x20that\x20we\x20can\x20convert\x20to\n\x20and\
    \x20from\x20\x20RFC\x203339\x20date\x20strings.\n\x20See\x20[https://www\
    .ietf.org/rfc/rfc3339.txt](https://www.ietf.org/rfc/rfc3339.txt).\n\n\
    \x20Example\x201:\x20Compute\x20Timestamp\x20from\x20POSIX\x20`time()`.\
    \n\n\x20\x20\x20\x20\x20Timestamp\x20timestamp;\n\x20\x20\x20\x20\x20tim\
    estamp.set_seconds(time(NULL));\n\x20\x20\x20\x20\x20timestamp.set_nanos\
    (0);\n\n\x20Example\x202:\x20Compute\x20Timestamp\x20from\x20POSIX\x20`g\
    ettimeofday()`.\n\n\x20\x20\x20\x20\x20struct\x20timeval\x20tv;\n\x20\
    \x20\x20\x20\x20gettimeofday(&tv,\x20NULL);\n\n\x20\x20\x20\x20\x20Times\
    tamp\x20timestamp;\n\x20\x20\x20\x20\x20timestamp.set_seconds(tv.tv_sec)\
    ;\n\x20\x20\x20\x20\x20timestamp.set_nanos(tv.tv_usec\x20*\x201000);\n\n\
    \x20Example\x203:\x20Compute\x20Timestamp\x20from\x20Win32\x20`GetSystem\
    TimeAsFileTime()`.\n\n\x20\x20\x20\x20\x20FILETIME\x20ft;\n\x20\x20\x20\
    \x20\x20GetSystemTimeAsFileTime(&ft);\n\x20\x20\x20\x20\x20UINT64\x20tic\
    ks\x20=\x20(((UINT64)ft.dwHighDateTime)\x20<<\x2032)\x20|\x20ft.dwLowDat\
    eTime;\n\n\x20\x20\x20\x20\x20//\x20A\x20Windows\x20tick\x20is\x20100\
    \x20nanoseconds.\x20Windows\x20epoch\x201601-01-01T00:00:00Z\n\x20\x20\
    \x20\x20\x20//\x20is\x2011644473600\x20seconds\x20before\x20Unix\x20epoc\
    h\x201970-01-01T00:00:00Z.\n\x20\x20\x20\x20\x20Timestamp\x20timestamp;\
    \n\x20\x20\x20\x20\x20timestamp.set_seconds((INT64)\x20((ticks\x20/\x201\
    0000000)\x20-\x2011644473600LL));\n\x20\x20\x20\x20\x20timestamp.set_nan\
    os((INT32)\x20((ticks\x20%\x2010000000)\x20*\x20100));\n\n\x20Example\
    \x204:\x20Compute\x20Timestamp\x20from\x20Java\x20`System.currentTimeMil\
    lis()`.\n\n\x20\x20\x20\x20\x20long\x20millis\x20=\x20System.currentTime\
    Millis();\n\n\x20\x20\x20\x20\x20Timestamp\x20timestamp\x20=\x20Timestam\
    p.newBuilder().setSeconds(millis\x20/\x201000)\n\x20\x20\x20\x20\x20\x20\
    \x20\x20\x20.setNanos((int)\x20((millis\x20%\x201000)\x20*\x201000000)).\
    build();\n\n\n\x20Example\x205:\x20Compute\x20Timestamp\x20from\x20curre\
    nt\x20time\x20in\x20Python.\n\n\x20\x20\x20\x20\x20timestamp\x20=\x20Tim\
    estamp()\n\x20\x20\x20\x20\x20timestamp.GetCurrentTime()\n\n\n\n\n\n\x03\
    \x04\0\x01\x12\x03_\x08\x11\n\x9c\x01\n\x04\x04\0\x02\0\x12\x03d\x02\x14\
    \x1a\x8e\x01\x20Represents\x20seconds\x20of\x20UTC\x20time\x20since\x20U\
    nix\x20epoch\n\x201970-01-01T00:00:00Z.\x20Must\x20be\x20from\x200001-01\
    -01T00:00:00Z\x20to\n\x209999-12-31T23:59:59Z\x20inclusive.\n\n\r\n\x05\
    \x04\0\x02\0\x04\x12\x04d\x02_\x13\n\x0c\n\x05\x04\0\x02\0\x05\x12\x03d\
    \x02\x07\n\x0c\n\x05\x04\0\x02\0\x01\x12\x03d\x08\x0f\n\x0c\n\x05\x04\0\
    \x02\0\x03\x12\x03d\x12\x13\n\xe4\x01\n\x04\x04\0\x02\x01\x12\x03j\x02\
    \x12\x1a\xd6\x01\x20Non-negative\x20fractions\x20of\x20a\x20second\x20at\
    \x20nanosecond\x20resolution.\x20Negative\n\x20second\x20values\x20with\
    \x20fractions\x20must\x20still\x20have\x20non-negative\x20nanos\x20value\
    s\n\x20that\x20count\x20forward\x20in\x20time.\x20Must\x20be\x20from\x20\
    0\x20to\x20999,999,999\n\x20inclusive.\n\n\r\n\x05\x04\0\x02\x01\x04\x12\
    \x04j\x02d\x14\n\x0c\n\x05\x04\0\x02\x01\x05\x12\x03j\x02\x07\n\x0c\n\
    \x05\x04\0\x02\x01\x01\x12\x03j\x08\r\n\x0c\n\x05\x04\0\x02\x01\x03\x12\
    \x03j\x10\x11b\x06proto3\
";

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}
