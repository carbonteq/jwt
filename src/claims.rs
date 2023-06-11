use napi_derive::napi;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

#[napi(object)]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ClaimOpts {
  // Recipient for which the JWT is intended
  #[serde(skip_serializing_if = "Option::is_none")]
  pub aud: Option<String>,
  // Time at which the JWT was issued (as UTC timestamp, seconds from epoch time)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub iat: Option<Number>,
  // Issuer of JWT
  #[serde(skip_serializing_if = "Option::is_none")]
  pub iss: Option<String>,
  // [JWT id] Unique identifier
  #[serde(skip_serializing_if = "Option::is_none")]
  pub jti: Option<String>,
  // [not-before-time] Time before which the JWT must not be accepted for processing (as UTC timestamp, seconds from epoch time)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub nbf: Option<Number>,
  // Subject of JWT (the user)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub sub: Option<String>,
}

// impl Default for ClaimOpts {
//   fn default() -> Self {
//     Self {
//       aud: None,
//       iat: None,
//       iss: None,
//       jti: None,
//       nbf: None,
//       sub: None,
//       // aud: Default::default(),
//       // iat: Default::default(),
//       // iss: Default::default(),
//       // jti: Default::default(),
//       // nbf: Default::default(),
//       // sub: Default::default(),
//     }
//   }
// }

#[napi]
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
  pub data: Map<String, Value>,
  // Time after which the JWT expires (as UTC timestamp, seconds from epoch time)
  pub exp: Number,

  // Recipient for which the JWT is intended
  #[serde(skip_serializing_if = "Option::is_none")]
  pub aud: Option<String>,
  // Time at which the JWT was issued (as UTC timestamp, seconds from epoch time)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub iat: Option<Number>,
  // Issuer of JWT
  #[serde(skip_serializing_if = "Option::is_none")]
  pub iss: Option<String>,
  // [JWT id] Unique identifier
  #[serde(skip_serializing_if = "Option::is_none")]
  pub jti: Option<String>,
  // [not-before-time] Time before which the JWT must not be accepted for processing (as UTC timestamp, seconds from epoch time)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub nbf: Option<Number>,
  // Subject of JWT (the user)
  #[serde(skip_serializing_if = "Option::is_none")]
  pub sub: Option<String>,
}

#[napi]
impl Claims {
  #[napi(constructor)]
  pub fn new(data: Map<String, Value>, expires_in_seconds: u32, opts: Option<ClaimOpts>) -> Self {
    let exp_val = jsonwebtoken::get_current_timestamp() + u64::from(expires_in_seconds);
    let exp = Number::from(exp_val);

    let opts = opts.unwrap_or_default();

    Self {
      data,
      exp,
      aud: opts.aud,
      iat: opts.iat,
      iss: opts.iss,
      jti: opts.jti,
      nbf: opts.nbf,
      sub: opts.sub,
    }
  }
}
