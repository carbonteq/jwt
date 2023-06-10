#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

#[napi]
pub fn sum(a: i32, b: i32) -> i32 {
  a + b
}

#[napi]
pub fn mul(a: i32, b: i32) -> i64 {
  i64::from(a) * i64::from(b)
}
