use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use napi::bindgen_prelude::Buffer;
use napi::Either;
use napi_derive::napi;

use crate::claims::{ClaimOpts, Claims};

#[napi]
pub struct JwtClient {
  encoding_key: EncodingKey,
  decoding_key: DecodingKey,
  header: Header,
  validation: Validation,
  // no_valid: Validation,
}

#[napi]
impl JwtClient {
  #[inline]
  fn from_key(key: &[u8]) -> Self {
    let encoding_key = EncodingKey::from_secret(key);
    let decoding_key = DecodingKey::from_secret(key);
    // let mut no_valid = Validation::new(jsonwebtoken::Algorithm::HS256);
    // no_valid.validate_exp = false;
    // no_valid.required_spec_claims = HashSet::new();
    // no_valid.insecure_disable_signature_validation();

    Self {
      encoding_key,
      decoding_key,
      header: Header::default(),
      validation: Validation::default(),
      // no_valid,
    }
  }

  #[napi(constructor)]
  pub fn new(secret_key: Either<String, Buffer>) -> Self {
    match secret_key {
      Either::A(s) => Self::from_key(s.as_bytes()),
      Either::B(buff) => Self::from_key(&buff),
    }
  }

  #[napi]
  pub fn sign(
    &self,
    data: serde_json::Map<String, serde_json::Value>,
    expires_in_seconds: u32,
    claim_opts: Option<ClaimOpts>,
  ) -> String {
    let claims = Claims::new(data, expires_in_seconds, claim_opts);

    jsonwebtoken::encode(&self.header, &claims, &self.encoding_key).unwrap()
    // self.sign_claims(&claims)
  }

  // #[napi]
  // pub fn sign_claims(&self, claims: &Claims) -> String {
  //   jsonwebtoken::encode(&self.header, claims, &self.encoding_key).unwrap()
  // }

  #[napi]
  pub fn verify(&self, token: String) -> napi::Result<Claims> {
    let decode_res = jsonwebtoken::decode::<Claims>(&token, &self.decoding_key, &self.validation);

    match decode_res {
      Ok(token_data) => napi::Result::Ok(token_data.claims),
      Err(e) => {
        let err = napi::Error::new(napi::Status::Unknown, e.to_string());
        napi::Result::Err(err)
      }
    }
  }

  // #[napi]
  // pub fn decode(&self, token: String) -> Claims {
  //   jsonwebtoken::decode::<Claims>(&token, &self.decoding_key, &self.no_valid)
  //     .unwrap()
  //     .claims
  // }
}
