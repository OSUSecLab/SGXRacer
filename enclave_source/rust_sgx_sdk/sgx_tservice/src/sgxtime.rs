// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use sgx_types::*;
use core::cmp::Ordering;
use core::fmt;

/// timestamp contains time in seconds and source_nonce contains nonce associate with the time.
#[derive(Copy, Clone, Debug, Default)]
pub struct SgxTime {
    timestamp: sgx_time_t,
    source_nonce: sgx_time_source_nonce_t,
}

pub type Duration = sgx_time_t;

pub enum SgxTimeError {
    TimeStamp(Duration),
    TimeSourceChanged,
    SgxStatus(sgx_status_t),
}

impl SgxTimeError {
    pub fn __description(&self) -> &str {
        match *self {
           SgxTimeError::TimeStamp(_) => "other time was not earlier than self",
           SgxTimeError::TimeSourceChanged => "time source is changed",
           SgxTimeError::SgxStatus(ref status) => status.__description(),
        }
    }
}

impl fmt::Display for SgxTimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
           SgxTimeError::TimeStamp(_) => write!(f, "second time provided was later than self"),
           SgxTimeError::TimeSourceChanged => write!(f, "time source does not match"),
           SgxTimeError::SgxStatus(status) => status.fmt(f),
        }
    }
}

impl PartialEq for SgxTime {
    fn eq(&self, other: &SgxTime) -> bool {
        self.timestamp == other.timestamp && self.source_nonce == other.source_nonce
    }
}

impl Eq for SgxTime {}

impl PartialOrd for SgxTime {

    fn partial_cmp(&self, other: &SgxTime) -> Option<Ordering> {

        if self.source_nonce == other.source_nonce {
            Some(self.timestamp.cmp(&other.timestamp))
        } else {
            None
        }
    }
}

impl SgxTime {

    pub fn now() -> Result<SgxTime, SgxTimeError> {

        let mut timestamp: sgx_time_t = 0;
        let mut source_nonce: sgx_time_source_nonce_t = Default::default();

        let ret = rsgx_get_trusted_time(&mut timestamp, &mut source_nonce);
        match ret {
            sgx_status_t::SGX_SUCCESS => Ok(SgxTime{timestamp, source_nonce}),
            _ => Err(SgxTimeError::SgxStatus(ret)),
        }
    }

    pub fn duration_since(&self, earlier: &SgxTime) -> Result<Duration, SgxTimeError> {

        if self.source_nonce == earlier.source_nonce {

            if self.timestamp >= earlier.timestamp {
                Ok(self.timestamp - earlier.timestamp)
            } else {
                Err(SgxTimeError::TimeStamp(earlier.timestamp - self.timestamp))
            }
        } else {
            Err(SgxTimeError::TimeSourceChanged)
        }
    }

    pub fn elapsed(&self) -> Result<Duration, SgxTimeError> {

        SgxTime::now().and_then(|t| t.duration_since(self))
    }

    pub fn add_duration(&self, other: Duration) -> Option<SgxTime> {

        self.timestamp.checked_add(other).map(|secs|
            SgxTime{ timestamp: secs, source_nonce: self.source_nonce }
        )
    }

    pub fn sub_duration(&self, other: Duration) -> Option<SgxTime> {

        self.timestamp.checked_sub(other).map(|secs|
            SgxTime{ timestamp: secs, source_nonce: self.source_nonce }
        )
    }

    pub fn get_secs(&self) -> sgx_time_t { self.timestamp }

    pub fn get_source_nonce(&self) -> sgx_time_source_nonce_t { self.source_nonce }
}

///
/// rsgx_get_trusted_time gets trusted time from the AE service.
///
/// # Description
///
/// current_time contains time in seconds and time_source_nonce contains nonce associate with the time.
/// The caller should compare time_source_nonce against the value returned from the previous call of
/// this API if it needs to calculate the time passed between two readings of the Trusted Timer. If the
/// time_source_nonce of the two readings do not match, the difference between the two readings does not
/// necessarily reflect time passed.
///
/// The caller should call rsgx_create_pse_session to establish a session with the platform service enclave
/// before calling this API.
///
/// # Parameters
///
/// **current_time**
///
/// Trusted Time Stamp in seconds relative to a reference point. The reference point does not change as long as
/// the time_source_nonce has not changed.
///
/// **time_source_nonce**
///
/// A pointer to the buffer that receives the nonce which indicates time source.
///
/// # Requirements
///
/// Header: sgx_tae_service.edl
///
/// Library: libsgx_tservice.a
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// Any of the pointers is invalid.
///
/// **SGX_ERROR_AE_SESSION_INVALID**
///
/// Session is not created or has been closed by architectural enclave service.
///
/// **SGX_ERROR_SERVICE_UNAVAILABLE**
///
/// The AE service did not respond or the requested service is not supported.
///
/// **SGX_ERROR_SERVICE_TIMEOUT**
///
/// A request to the AE service timed out.
///
/// **SGX_ERROR_NETWORK_FAILURE**
///
/// Network connecting or proxy setting issue was encountered.
///
/// **SGX_ERROR_OUT_OF_MEMORY**
///
/// Not enough memory is available to complete this operation.
///
/// **SGX_ERROR_OUT_OF_EPC**
///
/// There is not enough EPC memory to load one of the Architecture Enclaves needed to complete this operation.
///
/// **SGX_ERROR_UNEXPECTED**
///
/// Indicates an unexpected error occurs.
///
fn rsgx_get_trusted_time(current_time: &mut sgx_time_t,
                         time_source_nonce: &mut sgx_time_source_nonce_t) -> sgx_status_t {

    unsafe {
        sgx_get_trusted_time(current_time as * mut sgx_time_t, time_source_nonce as * mut sgx_time_source_nonce_t)
    }
}
