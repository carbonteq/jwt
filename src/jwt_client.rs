use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

use crate::claims::{ClaimOpts, Claims};

#[napi]
pub struct JwtClient {
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
  pub fn sign(
    &self,
    data: serde_json::Map<String, serde_json::Value>,
    expires_in_seconds: u32,
    claim_opts: Option<ClaimOpts>,
  ) -> String {
    let claims = Claims::new(data, expires_in_seconds, claim_opts);

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
  pub fn verify_and_decode(&self, token: String) -> napi::Result<Claims> {
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
