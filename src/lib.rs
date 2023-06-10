#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use napi::bindgen_prelude::Buffer;
use serde::{Deserialize, Serialize};

#[napi]
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
  payload: Vec<u8>,
  exp: u64,
}

#[napi]
impl Claims {
  #[napi(constructor)]
  pub fn new(payload: String, expires_in_ms: u32) -> Self {
    let exp = jsonwebtoken::get_current_timestamp() + u64::from(expires_in_ms);
    Self {
      payload: payload.as_bytes().to_vec(),
      exp,
    }
  }
}

#[napi]
struct JwtClient {
  encoding_key: EncodingKey,
  decoding_key: DecodingKey,
  header: Header,
  validation: Validation,
}

#[napi]
impl JwtClient {
  #[inline]
  fn from_key(key: &[u8]) -> Self {
    let encoding_key = EncodingKey::from_secret(key);
    let decoding_key = DecodingKey::from_secret(key);

    Self {
      encoding_key,
      decoding_key,
      header: Header::default(),
      validation: Validation::default(),
    }
  }

  #[napi(constructor)]
  pub fn new(secret_key: String) -> Self {
    let key = secret_key.as_bytes();
    Self::from_key(key)
  }

  #[napi(factory)]
  pub fn from_buffer_key(secret_key: Buffer) -> Self {
    Self::from_key(&secret_key)
  }

  #[napi]
  pub fn sign(&self, payload: String, expires_in_ms: u32) -> String {
    let claims = Claims::new(payload, expires_in_ms);

    self.sign_claims(&claims)
  }

  #[napi]
  pub fn sign_claims(&self, claims: &Claims) -> String {
    jsonwebtoken::encode(&self.header, claims, &self.encoding_key).unwrap()
  }

  #[napi]
  pub fn verify(&self, token: String) -> bool {
    jsonwebtoken::decode::<Claims>(&token, &self.decoding_key, &self.validation).is_ok()
  }

  #[napi]
  pub fn decode(&self, token: String) -> napi::Result<Claims> {
    let decode_res = jsonwebtoken::decode::<Claims>(&token, &self.decoding_key, &self.validation);

    match decode_res {
      Ok(token_data) => napi::Result::Ok(token_data.claims),
      Err(e) => {
        let err = napi::Error::new(napi::Status::Unknown, e.to_string());
        napi::Result::Err(err)
      }
    }
  }
}
