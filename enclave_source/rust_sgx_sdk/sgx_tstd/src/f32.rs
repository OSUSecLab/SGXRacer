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

//! This module provides constants which are specific to the implementation
//! of the `f32` floating point data type.
//!
//! *[See also the `f32` primitive type](../../std/primitive.f32.html).*
//!
//! Mathematically significant numbers are provided in the `consts` sub-module.

#![allow(missing_docs)]

use intrinsics;
use sys::cmath;

pub use core::f32::{RADIX, MANTISSA_DIGITS, DIGITS, EPSILON};
pub use core::f32::{MIN_EXP, MAX_EXP, MIN_10_EXP};
pub use core::f32::{MAX_10_EXP, NAN, INFINITY, NEG_INFINITY};
pub use core::f32::{MIN, MIN_POSITIVE, MAX};
pub use core::f32::consts;

#[lang = "f32_runtime"]
impl f32 {
    /// Returns the largest integer less than or equal to a number.
    ///
    /// # Examples
    ///
    /// ```
    /// let f = 3.99_f32;
    /// let g = 3.0_f32;
    ///
    /// assert_eq!(f.floor(), 3.0);
    /// assert_eq!(g.floor(), 3.0);
    /// ```
    #[inline]
    pub fn floor(self) -> f32 {
        // On MSVC LLVM will lower many math intrinsics to a call to the
        // corresponding function. On MSVC, however, many of these functions
        // aren't actually available as symbols to call, but rather they are all
        // `static inline` functions in header files. This means that from a C
        // perspective it's "compatible", but not so much from an ABI
        // perspective (which we're worried about).
        //
        // The inline header functions always just cast to a f64 and do their
        // operation, so we do that here as well, but only for MSVC targets.
        //
        // Note that there are many MSVC-specific float operations which
        // redirect to this comment, so `floorf` is just one case of a missing
        // function on MSVC, but there are many others elsewhere.
        #[cfg(target_env = "msvc")]
        return (self as f64).floor() as f32;
        #[cfg(not(target_env = "msvc"))]
        return unsafe { intrinsics::floorf32(self) };
    }

    /// Returns the smallest integer greater than or equal to a number.
    ///
    /// # Examples
    ///
    /// ```
    /// let f = 3.01_f32;
    /// let g = 4.0_f32;
    ///
    /// assert_eq!(f.ceil(), 4.0);
    /// assert_eq!(g.ceil(), 4.0);
    /// ```
    #[inline]
    pub fn ceil(self) -> f32 {
        // see notes above in `floor`
        #[cfg(target_env = "msvc")]
        return (self as f64).ceil() as f32;
        #[cfg(not(target_env = "msvc"))]
        return unsafe { intrinsics::ceilf32(self) };
    }

    /// Returns the nearest integer to a number. Round half-way cases away from
    /// `0.0`.
    ///
    /// # Examples
    ///
    /// ```
    /// let f = 3.3_f32;
    /// let g = -3.3_f32;
    ///
    /// assert_eq!(f.round(), 3.0);
    /// assert_eq!(g.round(), -3.0);
    /// ```
    #[inline]
    pub fn round(self) -> f32 {
        unsafe { intrinsics::roundf32(self) }
    }

    /// Returns the integer part of a number.
    ///
    /// # Examples
    ///
    /// ```
    /// let f = 3.3_f32;
    /// let g = -3.7_f32;
    ///
    /// assert_eq!(f.trunc(), 3.0);
    /// assert_eq!(g.trunc(), -3.0);
    /// ```
    #[inline]
    pub fn trunc(self) -> f32 {
        unsafe { intrinsics::truncf32(self) }
    }

    /// Returns the fractional part of a number.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 3.5_f32;
    /// let y = -3.5_f32;
    /// let abs_difference_x = (x.fract() - 0.5).abs();
    /// let abs_difference_y = (y.fract() - (-0.5)).abs();
    ///
    /// assert!(abs_difference_x <= f32::EPSILON);
    /// assert!(abs_difference_y <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn fract(self) -> f32 { self - self.trunc() }

    /// Computes the absolute value of `self`. Returns `NAN` if the
    /// number is `NAN`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 3.5_f32;
    /// let y = -3.5_f32;
    ///
    /// let abs_difference_x = (x.abs() - x).abs();
    /// let abs_difference_y = (y.abs() - (-y)).abs();
    ///
    /// assert!(abs_difference_x <= f32::EPSILON);
    /// assert!(abs_difference_y <= f32::EPSILON);
    ///
    /// assert!(f32::NAN.abs().is_nan());
    /// ```
    #[inline]
    pub fn abs(self) -> f32 {
        unsafe { intrinsics::fabsf32(self) }
    }

    /// Returns a number that represents the sign of `self`.
    ///
    /// - `1.0` if the number is positive, `+0.0` or `INFINITY`
    /// - `-1.0` if the number is negative, `-0.0` or `NEG_INFINITY`
    /// - `NAN` if the number is `NAN`
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let f = 3.5_f32;
    ///
    /// assert_eq!(f.signum(), 1.0);
    /// assert_eq!(f32::NEG_INFINITY.signum(), -1.0);
    ///
    /// assert!(f32::NAN.signum().is_nan());
    /// ```
    #[inline]
    pub fn signum(self) -> f32 {
        if self.is_nan() {
            NAN
        } else {
            unsafe { intrinsics::copysignf32(1.0, self) }
        }
    }

    /// Fused multiply-add. Computes `(self * a) + b` with only one rounding
    /// error, yielding a more accurate result than an unfused multiply-add.
    ///
    /// Using `mul_add` can be more performant than an unfused multiply-add if
    /// the target architecture has a dedicated `fma` CPU instruction.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let m = 10.0_f32;
    /// let x = 4.0_f32;
    /// let b = 60.0_f32;
    ///
    /// // 100.0
    /// let abs_difference = (m.mul_add(x, b) - (m*x + b)).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn mul_add(self, a: f32, b: f32) -> f32 {
        unsafe { intrinsics::fmaf32(self, a, b) }
    }

    /// Calculates Euclidean division, the matching method for `mod_euc`.
    ///
    /// This computes the integer `n` such that
    /// `self = n * rhs + self.mod_euc(rhs)`.
    /// In other words, the result is `self / rhs` rounded to the integer `n`
    /// such that `self >= n * rhs`.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(euclidean_division)]
    /// let a: f32 = 7.0;
    /// let b = 4.0;
    /// assert_eq!(a.div_euc(b), 1.0); // 7.0 > 4.0 * 1.0
    /// assert_eq!((-a).div_euc(b), -2.0); // -7.0 >= 4.0 * -2.0
    /// assert_eq!(a.div_euc(-b), -1.0); // 7.0 >= -4.0 * -1.0
    /// assert_eq!((-a).div_euc(-b), 2.0); // -7.0 >= -4.0 * 2.0
    /// ```
    #[inline]
    pub fn div_euc(self, rhs: f32) -> f32 {
        let q = (self / rhs).trunc();
        if self % rhs < 0.0 {
            return if rhs > 0.0 { q - 1.0 } else { q + 1.0 }
        }
        q
    }

    /// Calculates the Euclidean modulo (self mod rhs), which is never negative.
    ///
    /// In particular, the result `n` satisfies `0 <= n < rhs.abs()`.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(euclidean_division)]
    /// let a: f32 = 7.0;
    /// let b = 4.0;
    /// assert_eq!(a.mod_euc(b), 3.0);
    /// assert_eq!((-a).mod_euc(b), 1.0);
    /// assert_eq!(a.mod_euc(-b), 3.0);
    /// assert_eq!((-a).mod_euc(-b), 1.0);
    /// ```
    #[inline]
    pub fn mod_euc(self, rhs: f32) -> f32 {
        let r = self % rhs;
        if r < 0.0 {
            r + rhs.abs()
        } else {
            r
        }
    }


    /// Raises a number to an integer power.
    ///
    /// Using this function is generally faster than using `powf`
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 2.0_f32;
    /// let abs_difference = (x.powi(2) - x*x).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn powi(self, n: i32) -> f32 {
        unsafe { intrinsics::powif32(self, n) }
    }

    /// Raises a number to a floating point power.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 2.0_f32;
    /// let abs_difference = (x.powf(2.0) - x*x).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn powf(self, n: f32) -> f32 {
        // see notes above in `floor`
        #[cfg(target_env = "msvc")]
        return (self as f64).powf(n as f64) as f32;
        #[cfg(not(target_env = "msvc"))]
        return unsafe { intrinsics::powf32(self, n) };
    }

    /// Takes the square root of a number.
    ///
    /// Returns NaN if `self` is a negative number.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let positive = 4.0_f32;
    /// let negative = -4.0_f32;
    ///
    /// let abs_difference = (positive.sqrt() - 2.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// assert!(negative.sqrt().is_nan());
    /// ```
    #[inline]
    pub fn sqrt(self) -> f32 {
        if self < 0.0 {
            NAN
        } else {
            unsafe { intrinsics::sqrtf32(self) }
        }
    }

    /// Returns `e^(self)`, (the exponential function).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let one = 1.0f32;
    /// // e^1
    /// let e = one.exp();
    ///
    /// // ln(e) - 1 == 0
    /// let abs_difference = (e.ln() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn exp(self) -> f32 {
        // see notes above in `floor`
        #[cfg(target_env = "msvc")]
        return (self as f64).exp() as f32;
        #[cfg(not(target_env = "msvc"))]
        return unsafe { intrinsics::expf32(self) };
    }

    /// Returns `2^(self)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let f = 2.0f32;
    ///
    /// // 2^2 - 4 == 0
    /// let abs_difference = (f.exp2() - 4.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn exp2(self) -> f32 {
        unsafe { intrinsics::exp2f32(self) }
    }

    /// Returns the natural logarithm of the number.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let one = 1.0f32;
    /// // e^1
    /// let e = one.exp();
    ///
    /// // ln(e) - 1 == 0
    /// let abs_difference = (e.ln() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn ln(self) -> f32 {
        // see notes above in `floor`
        #[cfg(target_env = "msvc")]
        return (self as f64).ln() as f32;
        #[cfg(not(target_env = "msvc"))]
        return unsafe { intrinsics::logf32(self) };
    }

    /// Returns the logarithm of the number with respect to an arbitrary base.
    ///
    /// The result may not be correctly rounded owing to implementation details;
    /// `self.log2()` can produce more accurate results for base 2, and
    /// `self.log10()` can produce more accurate results for base 10.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let five = 5.0f32;
    ///
    /// // log5(5) - 1 == 0
    /// let abs_difference = (five.log(5.0) - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn log(self, base: f32) -> f32 { self.ln() / base.ln() }

    /// Returns the base 2 logarithm of the number.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let two = 2.0f32;
    ///
    /// // log2(2) - 1 == 0
    /// let abs_difference = (two.log2() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn log2(self) -> f32 {
        #[cfg(target_os = "android")]
        return ::sys::android::log2f32(self);
        #[cfg(not(target_os = "android"))]
        return unsafe { intrinsics::log2f32(self) };
    }

    /// Returns the base 10 logarithm of the number.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let ten = 10.0f32;
    ///
    /// // log10(10) - 1 == 0
    /// let abs_difference = (ten.log10() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn log10(self) -> f32 {
        // see notes above in `floor`
        #[cfg(target_env = "msvc")]
        return (self as f64).log10() as f32;
        #[cfg(not(target_env = "msvc"))]
        return unsafe { intrinsics::log10f32(self) };
    }

    /// Takes the cubic root of a number.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 8.0f32;
    ///
    /// // x^(1/3) - 2 == 0
    /// let abs_difference = (x.cbrt() - 2.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn cbrt(self) -> f32 {
        unsafe { cmath::cbrtf(self) }
    }

    /// Calculates the length of the hypotenuse of a right-angle triangle given
    /// legs of length `x` and `y`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 2.0f32;
    /// let y = 3.0f32;
    ///
    /// // sqrt(x^2 + y^2)
    /// let abs_difference = (x.hypot(y) - (x.powi(2) + y.powi(2)).sqrt()).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn hypot(self, other: f32) -> f32 {
        unsafe { cmath::hypotf(self, other) }
    }

    /// Computes the sine of a number (in radians).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = f32::consts::PI/2.0;
    ///
    /// let abs_difference = (x.sin() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn sin(self) -> f32 {
        // see notes in `core::f32::Float::floor`
        #[cfg(target_env = "msvc")]
        return (self as f64).sin() as f32;
        #[cfg(not(target_env = "msvc"))]
        return unsafe { intrinsics::sinf32(self) };
    }

    /// Computes the cosine of a number (in radians).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 2.0*f32::consts::PI;
    ///
    /// let abs_difference = (x.cos() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn cos(self) -> f32 {
        // see notes in `core::f32::Float::floor`
        #[cfg(target_env = "msvc")]
        return (self as f64).cos() as f32;
        #[cfg(not(target_env = "msvc"))]
        return unsafe { intrinsics::cosf32(self) };
    }

    /// Computes the tangent of a number (in radians).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = f32::consts::PI / 4.0;
    /// let abs_difference = (x.tan() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn tan(self) -> f32 {
        unsafe { cmath::tanf(self) }
    }

    /// Computes the arcsine of a number. Return value is in radians in
    /// the range [-pi/2, pi/2] or NaN if the number is outside the range
    /// [-1, 1].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let f = f32::consts::PI / 2.0;
    ///
    /// // asin(sin(pi/2))
    /// let abs_difference = (f.sin().asin() - f32::consts::PI / 2.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn asin(self) -> f32 {
        unsafe { cmath::asinf(self) }
    }

    /// Computes the arccosine of a number. Return value is in radians in
    /// the range [0, pi] or NaN if the number is outside the range
    /// [-1, 1].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let f = f32::consts::PI / 4.0;
    ///
    /// // acos(cos(pi/4))
    /// let abs_difference = (f.cos().acos() - f32::consts::PI / 4.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn acos(self) -> f32 {
        unsafe { cmath::acosf(self) }
    }

    /// Computes the arctangent of a number. Return value is in radians in the
    /// range [-pi/2, pi/2];
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let f = 1.0f32;
    ///
    /// // atan(tan(1))
    /// let abs_difference = (f.tan().atan() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn atan(self) -> f32 {
        unsafe { cmath::atanf(self) }
    }

    /// Computes the four quadrant arctangent of `self` (`y`) and `other` (`x`) in radians.
    ///
    /// * `x = 0`, `y = 0`: `0`
    /// * `x >= 0`: `arctan(y/x)` -> `[-pi/2, pi/2]`
    /// * `y >= 0`: `arctan(y/x) + pi` -> `(pi/2, pi]`
    /// * `y < 0`: `arctan(y/x) - pi` -> `(-pi, -pi/2)`
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let pi = f32::consts::PI;
    /// // Positive angles measured counter-clockwise
    /// // from positive x axis
    /// // -pi/4 radians (45 deg clockwise)
    /// let x1 = 3.0f32;
    /// let y1 = -3.0f32;
    ///
    /// // 3pi/4 radians (135 deg counter-clockwise)
    /// let x2 = -3.0f32;
    /// let y2 = 3.0f32;
    ///
    /// let abs_difference_1 = (y1.atan2(x1) - (-pi/4.0)).abs();
    /// let abs_difference_2 = (y2.atan2(x2) - 3.0*pi/4.0).abs();
    ///
    /// assert!(abs_difference_1 <= f32::EPSILON);
    /// assert!(abs_difference_2 <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn atan2(self, other: f32) -> f32 {
        unsafe { cmath::atan2f(self, other) }
    }

    /// Simultaneously computes the sine and cosine of the number, `x`. Returns
    /// `(sin(x), cos(x))`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = f32::consts::PI/4.0;
    /// let f = x.sin_cos();
    ///
    /// let abs_difference_0 = (f.0 - x.sin()).abs();
    /// let abs_difference_1 = (f.1 - x.cos()).abs();
    ///
    /// assert!(abs_difference_0 <= f32::EPSILON);
    /// assert!(abs_difference_1 <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn sin_cos(self) -> (f32, f32) {
        (self.sin(), self.cos())
    }

    /// Returns `e^(self) - 1` in a way that is accurate even if the
    /// number is close to zero.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 6.0f32;
    ///
    /// // e^(ln(6)) - 1
    /// let abs_difference = (x.ln().exp_m1() - 5.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn exp_m1(self) -> f32 {
        unsafe { cmath::expm1f(self) }
    }

    /// Returns `ln(1+n)` (natural logarithm) more accurately than if
    /// the operations were performed separately.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = f32::consts::E - 1.0;
    ///
    /// // ln(1 + (e - 1)) == ln(e) == 1
    /// let abs_difference = (x.ln_1p() - 1.0).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn ln_1p(self) -> f32 {
        unsafe { cmath::log1pf(self) }
    }

    /// Hyperbolic sine function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let e = f32::consts::E;
    /// let x = 1.0f32;
    ///
    /// let f = x.sinh();
    /// // Solving sinh() at 1 gives `(e^2-1)/(2e)`
    /// let g = (e*e - 1.0)/(2.0*e);
    /// let abs_difference = (f - g).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn sinh(self) -> f32 {
        unsafe { cmath::sinhf(self) }
    }

    /// Hyperbolic cosine function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let e = f32::consts::E;
    /// let x = 1.0f32;
    /// let f = x.cosh();
    /// // Solving cosh() at 1 gives this result
    /// let g = (e*e + 1.0)/(2.0*e);
    /// let abs_difference = (f - g).abs();
    ///
    /// // Same result
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn cosh(self) -> f32 {
        unsafe { cmath::coshf(self) }
    }

    /// Hyperbolic tangent function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let e = f32::consts::E;
    /// let x = 1.0f32;
    ///
    /// let f = x.tanh();
    /// // Solving tanh() at 1 gives `(1 - e^(-2))/(1 + e^(-2))`
    /// let g = (1.0 - e.powi(-2))/(1.0 + e.powi(-2));
    /// let abs_difference = (f - g).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn tanh(self) -> f32 {
        unsafe { cmath::tanhf(self) }
    }

    /// Inverse hyperbolic sine function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 1.0f32;
    /// let f = x.sinh().asinh();
    ///
    /// let abs_difference = (f - x).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn asinh(self) -> f32 {
        if self == NEG_INFINITY {
            NEG_INFINITY
        } else {
            (self + ((self * self) + 1.0).sqrt()).ln()
        }
    }

    /// Inverse hyperbolic cosine function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let x = 1.0f32;
    /// let f = x.cosh().acosh();
    ///
    /// let abs_difference = (f - x).abs();
    ///
    /// assert!(abs_difference <= f32::EPSILON);
    /// ```
    #[inline]
    pub fn acosh(self) -> f32 {
        match self {
            x if x < 1.0 => ::f32::NAN,
            x => (x + ((x * x) - 1.0).sqrt()).ln(),
        }
    }

    /// Inverse hyperbolic tangent function.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::f32;
    ///
    /// let e = f32::consts::E;
    /// let f = e.tanh().atanh();
    ///
    /// let abs_difference = (f - e).abs();
    ///
    /// assert!(abs_difference <= 1e-5);
    /// ```
    #[inline]
    pub fn atanh(self) -> f32 {
        0.5 * ((2.0 * self) / (1.0 - self)).ln_1p()
    }
}
