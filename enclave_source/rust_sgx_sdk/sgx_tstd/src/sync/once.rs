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

//! A "once initialization" primitive
//!
//! This primitive is meant to be used to run one-time initialization. An
//! example use case would be for initializing an FFI library.

// A "once" is a relatively simple primitive, and it's also typically provided
// by the OS as well (see `pthread_once` or `InitOnceExecuteOnce`). The OS
// primitives, however, tend to have surprising restrictions, such as the Unix
// one doesn't allow an argument to be passed to the function.
//
// As a result, we end up implementing it ourselves in the standard library.
// This also gives us the opportunity to optimize the implementation a bit which
// should help the fast path on call sites. Consequently, let's explain how this
// primitive works now!
//
// So to recap, the guarantees of a Once are that it will call the
// initialization closure at most once, and it will never return until the one
// that's running has finished running. This means that we need some form of
// blocking here while the custom callback is running at the very least.
// Additionally, we add on the restriction of **poisoning**. Whenever an
// initialization closure panics, the Once enters a "poisoned" state which means
// that all future calls will immediately panic as well.
//
// So to implement this, one might first reach for a `StaticMutex`, but those
// unfortunately need to be deallocated (e.g. call `destroy()`) to free memory
// on all OSes (some of the BSDs allocate memory for mutexes). It also gets a
// lot harder with poisoning to figure out when the mutex needs to be
// deallocated because it's not after the closure finishes, but after the first
// successful closure finishes.
//
// All in all, this is instead implemented with atomics and lock-free
// operations! Whee! Each `Once` has one word of atomic state, and this state is
// CAS'd on to determine what to do. There are four possible state of a `Once`:
//
// * Incomplete - no initialization has run yet, and no thread is currently
//                using the Once.
// * Poisoned - some thread has previously attempted to initialize the Once, but
//              it panicked, so the Once is now poisoned. There are no other
//              threads currently accessing this Once.
// * Running - some thread is currently attempting to run initialization. It may
//             succeed, so all future threads need to wait for it to finish.
//             Note that this state is accompanied with a payload, described
//             below.
// * Complete - initialization has completed and all future calls should finish
//              immediately.
//
// With 4 states we need 2 bits to encode this, and we use the remaining bits
// in the word we have allocated as a queue of threads waiting for the thread
// responsible for entering the RUNNING state. This queue is just a linked list
// of Waiter nodes which is monotonically increasing in size. Each node is
// allocated on the stack, and whenever the running closure finishes it will
// consume the entire queue and notify all waiters they should try again.
//
// You'll find a few more details in the implementation, but that's the gist of
// it!

use core::marker;
use core::ptr;
use core::fmt;
use core::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use thread::{self, SgxThread};

/// A synchronization primitive which can be used to run a one-time global
/// initialization. Useful for one-time initialization for FFI or related
/// functionality. This type can only be constructed with the [`ONCE_INIT`]
/// value.
///
/// [`ONCE_INIT`]: constant.ONCE_INIT.html
///
pub struct Once {
    // This `state` word is actually an encoded version of just a pointer to a
    // `Waiter`, so we add the `PhantomData` appropriately.
    state: AtomicUsize,
    _marker: marker::PhantomData<* mut Waiter>,
}

// The `PhantomData` of a raw pointer removes these two auto traits, but we
// enforce both below in the implementation so this should be safe to add.
unsafe impl Sync for Once {}
unsafe impl Send for Once {}

/// State yielded to the [`call_once_force`] method which can be used to query
/// whether the [`Once`] was previously poisoned or not.
///
/// [`call_once_force`]: struct.Once.html#method.call_once_force
/// [`Once`]: struct.Once.html
#[derive(Debug)]
pub struct OnceState {
    poisoned: bool,
}

/// Initialization value for static [`Once`] values.
///
/// [`Once`]: struct.Once.html
///
pub const ONCE_INIT: Once = Once::new();

// Four states that a Once can be in, encoded into the lower bits of `state` in
// the Once structure.
const INCOMPLETE: usize = 0x0;
const POISONED: usize = 0x1;
const RUNNING: usize = 0x2;
const COMPLETE: usize = 0x3;

// Mask to learn about the state. All other bits are the queue of waiters if
// this is in the RUNNING state.
const STATE_MASK: usize = 0x3;

// Representation of a node in the linked list of waiters in the RUNNING state.
struct Waiter {
    thread: Option<SgxThread>,
    signaled: AtomicBool,
    next: * mut Waiter,
}

// Helper struct used to clean up after a closure call with a `Drop`
// implementation to also run on panic.
struct Finish {
    panicked: bool,
    me: &'static Once,
}

impl Once {
    /// Creates a new `Once` value.
    pub const fn new() -> Once {
        Once {
            state: AtomicUsize::new(INCOMPLETE),
            _marker: marker::PhantomData,
        }
    }

    /// Performs an initialization routine once and only once. The given closure
    /// will be executed if this is the first time `call_once` has been called,
    /// and otherwise the routine will *not* be invoked.
    ///
    /// This method will block the calling thread if another initialization
    /// routine is currently running.
    ///
    /// When this function returns, it is guaranteed that some initialization
    /// has run and completed (it may not be the closure specified). It is also
    /// guaranteed that any memory writes performed by the executed closure can
    /// be reliably observed by other threads at this point (there is a
    /// happens-before relation between the closure and code executing after the
    /// return).
    ///
    /// # Panics
    ///
    /// The closure `f` will only be executed once if this is called
    /// concurrently amongst many threads. If that closure panics, however, then
    /// it will *poison* this `Once` instance, causing all future invocations of
    /// `call_once` to also panic.
    ///
    /// This is similar to [poisoning with mutexes][poison].
    ///
    /// [poison]: struct.Mutex.html#poisoning
    pub fn call_once<F>(&'static self, f: F) where F: FnOnce() {
        // Fast path, just see if we've completed initialization.
        if self.state.load(Ordering::SeqCst) == COMPLETE {
            return
        }

        let mut f = Some(f);
        self.call_inner(false, &mut |_| f.take().unwrap()());
    }

    /// Performs the same function as [`call_once`] except ignores poisoning.
    ///
    /// [`call_once`]: struct.Once.html#method.call_once
    ///
    /// If this `Once` has been poisoned (some initialization panicked) then
    /// this function will continue to attempt to call initialization functions
    /// until one of them doesn't panic.
    ///
    /// The closure `f` is yielded a [`OnceState`] structure which can be used to query the
    /// state of this `Once` (whether initialization has previously panicked or
    /// not).
    ///
    /// [`OnceState`]: struct.OnceState.html
    pub fn call_once_force<F>(&'static self, f: F) where F: FnOnce(&OnceState) {
        // same as above, just with a different parameter to `call_inner`.
        if self.state.load(Ordering::SeqCst) == COMPLETE {
            return
        }

        let mut f = Some(f);
        self.call_inner(true, &mut |p| {
            f.take().unwrap()(&OnceState { poisoned: p })
        });
    }

    // This is a non-generic function to reduce the monomorphization cost of
    // using `call_once` (this isn't exactly a trivial or small implementation).
    //
    // Additionally, this is tagged with `#[cold]` as it should indeed be cold
    // and it helps let LLVM know that calls to this function should be off the
    // fast path. Essentially, this should help generate more straight line code
    // in LLVM.
    //
    // Finally, this takes an `FnMut` instead of a `FnOnce` because there's
    // currently no way to take an `FnOnce` and call it via virtual dispatch
    // without some allocation overhead.
    #[cold]
    fn call_inner(&'static self,
                  ignore_poisoning: bool,
                  init: &mut FnMut(bool)) {
        let mut state = self.state.load(Ordering::SeqCst);

        'outer: loop {
            match state {
                // If we're complete, then there's nothing to do, we just
                // jettison out as we shouldn't run the closure.
                COMPLETE => return,

                // If we're poisoned and we're not in a mode to ignore
                // poisoning, then we panic here to propagate the poison.
                POISONED if !ignore_poisoning => {
                    panic!("Once instance has previously been poisoned");
                }

                // Otherwise if we see a poisoned or otherwise incomplete state
                // we will attempt to move ourselves into the RUNNING state. If
                // we succeed, then the queue of waiters starts at null (all 0
                // bits).
                POISONED |
                INCOMPLETE => {
                    let old = self.state.compare_and_swap(state, RUNNING,
                                                          Ordering::SeqCst);
                    if old != state {
                        state = old;
                        continue
                    }

                    // Run the initialization routine, letting it know if we're
                    // poisoned or not. The `Finish` struct is then dropped, and
                    // the `Drop` implementation here is responsible for waking
                    // up other waiters both in the normal return and panicking
                    // case.
                    let mut complete = Finish {
                        panicked: true,
                        me: self,
                    };
                    init(state == POISONED);
                    complete.panicked = false;
                    return
                }

                // All other values we find should correspond to the RUNNING
                // state with an encoded waiter list in the more significant
                // bits. We attempt to enqueue ourselves by moving us to the
                // head of the list and bail out if we ever see a state that's
                // not RUNNING.
                _ => {
                    assert!(state & STATE_MASK == RUNNING);
                    let mut node = Waiter {
                        thread: Some(thread::current()),
                        signaled: AtomicBool::new(false),
                        next: ptr::null_mut(),
                    };
                    let me = &mut node as *mut Waiter as usize;
                    assert!(me & STATE_MASK == 0);

                    while state & STATE_MASK == RUNNING {
                        node.next = (state & !STATE_MASK) as *mut Waiter;
                        let old = self.state.compare_and_swap(state,
                                                              me | RUNNING,
                                                              Ordering::SeqCst);
                        if old != state {
                            state = old;
                            continue
                        }

                        // Once we've enqueued ourselves, wait in a loop.
                        // Afterwards reload the state and continue with what we
                        // were doing from before.
                        while !node.signaled.load(Ordering::SeqCst) {
                            thread::park();
                        }
                        state = self.state.load(Ordering::SeqCst);
                        continue 'outer
                    }
                }
            }
        }
    }
}

impl fmt::Debug for Once {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad("Once { .. }")
    }
}

impl Drop for Finish {
    fn drop(&mut self) {
        // Swap out our state with however we finished. We should only ever see
        // an old state which was RUNNING.
        let queue = if self.panicked {
            self.me.state.swap(POISONED, Ordering::SeqCst)
        } else {
            self.me.state.swap(COMPLETE, Ordering::SeqCst)
        };
        assert_eq!(queue & STATE_MASK, RUNNING);

        // Decode the RUNNING to a list of waiters, then walk that entire list
        // and wake them up. Note that it is crucial that after we store `true`
        // in the node it can be free'd! As a result we load the `thread` to
        // signal ahead of time and then unpark it after the store.
        unsafe {
            let mut queue = (queue & !STATE_MASK) as *mut Waiter;
            while !queue.is_null() {
                let next = (*queue).next;
                let thread = (*queue).thread.take().unwrap();
                (*queue).signaled.store(true, Ordering::SeqCst);
                thread.unpark();
                queue = next;
            }
        }
    }
}

impl OnceState {
    /// Returns whether the associated [`Once`] has been poisoned.
    ///
    /// Once an initialization routine for a [`Once`] has panicked it will forever
    /// indicate to future forced initialization routines that it is poisoned.
    ///
    /// [`Once`]: struct.Once.html
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
}