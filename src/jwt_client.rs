use jsonwebtoken::{DecodingKey, EncodingKey};
use napi::bindgen_prelude::Buffer;
use napi::Either;
use napi_derive::napi;

use crate::claims::{ClaimOpts, Claims};
use crate::errors::Error;
use crate::header::Header;
use crate::validation::Validation;

#[napi(object)]
#[derive(Default)]
pub struct JwtClientInitOpts {
  pub header: Option<Header>,
  pub validation: Option<Validation>,
}

#[napi]
pub struct JwtClient {
  encoding_key: jsonwebtoken::EncodingKey,
  decoding_key: jsonwebtoken::DecodingKey,
  header: jsonwebtoken::Header,
  validation: jsonwebtoken::Validation,
}

#[inline]
fn get_encoding_key(key: &[u8], algorithm: jsonwebtoken::Algorithm) -> Result<EncodingKey, Error> {
  use jsonwebtoken::Algorithm as Alg;

  let enc_key_res = match algorithm {
    // HMAC family
    Alg::HS256 | Alg::HS384 | Alg::HS512 => Ok(EncodingKey::from_secret(key)),

    // RSA family
    Alg::RS256 | Alg::RS384 | Alg::RS512 | Alg::PS256 | Alg::PS384 | Alg::PS512 => {
      EncodingKey::from_rsa_pem(key)
    }

    // EC family
    Alg::ES256 | Alg::ES384 => EncodingKey::from_ec_pem(key),

    // ED family
    Alg::EdDSA => EncodingKey::from_ed_pem(key),
  };

  enc_key_res.map_err(Error::from)
}

#[inline]
fn get_decoding_key(key: &[u8], algorithm: jsonwebtoken::Algorithm) -> Result<DecodingKey, Error> {
  use jsonwebtoken::Algorithm as Alg;

  let dec_key_res = match algorithm {
    // HMAC family
    Alg::HS256 | Alg::HS384 | Alg::HS512 => Ok(DecodingKey::from_secret(key)),

    // RSA family
    Alg::RS256 | Alg::RS384 | Alg::RS512 | Alg::PS256 | Alg::PS384 | Alg::PS512 => {
      DecodingKey::from_rsa_pem(key)
    }

    // EC family
    Alg::ES256 | Alg::ES384 => DecodingKey::from_ec_pem(key),

    // ED family
    Alg::EdDSA => DecodingKey::from_ed_pem(key),
  };

  dec_key_res.map_err(Error::from)
}

#[napi]
impl JwtClient {
  #[napi(constructor)]
  /// For symetric key based signatures
  pub fn new(
    secret_key: Either<String, Buffer>,
    opts: Option<JwtClientInitOpts>,
  ) -> Result<Self, Error> {
    let opts = opts.unwrap_or_default();
    let header: jsonwebtoken::Header = opts.header.unwrap_or_default().into();
    let alg = header.alg;
    let validation: jsonwebtoken::Validation =
      opts.validation.unwrap_or_default().for_jsonwebtoken(alg);

    let (encoding_key, decoding_key) = match secret_key {
      Either::A(s) => {
        let sb = s.as_bytes();
        let encoding_key = get_encoding_key(sb, alg)?;
        let decoding_key = get_decoding_key(sb, alg)?;

        (encoding_key, decoding_key)
      }
      Either::B(buff) => {
        let encoding_key = get_encoding_key(&buff, alg)?;
        let decoding_key = get_decoding_key(&buff, alg)?;

        (encoding_key, decoding_key)
      }
    };

    Ok(Self {
      header,
      encoding_key,
      decoding_key,
      validation,
    })
  }

  #[napi(factory)]
  /// For assymetric key based signatures
  pub fn with_pub_priv_keys(
    pub_key: Either<String, Buffer>,
    priv_key: Either<String, Buffer>,
    opts: Option<JwtClientInitOpts>,
  ) -> Result<Self, Error> {
    let opts = opts.unwrap_or_default();
    let header: jsonwebtoken::Header = opts.header.unwrap_or_default().into();
    let alg = header.alg;
    let validation: jsonwebtoken::Validation =
      opts.validation.unwrap_or_default().for_jsonwebtoken(alg);

    let encoding_key = match priv_key {
      Either::A(s) => get_encoding_key(s.as_bytes(), alg),
      Either::B(buff) => get_encoding_key(&buff, alg),
    }?;

    let decoding_key = match pub_key {
      Either::A(s) => get_decoding_key(s.as_bytes(), header.alg),
      Either::B(buff) => get_decoding_key(&buff, header.alg),
    }?;

    Ok(Self {
      header,
      validation,
      encoding_key,
      decoding_key,
    })
  }

  #[napi]
  pub fn sign(
    &self,
    data: serde_json::Map<String, serde_json::Value>,
    expires_in_seconds: u32,
    claim_opts: Option<ClaimOpts>,
  ) -> napi::Result<String> {
    let claims = Claims::new(data, expires_in_seconds, claim_opts);

    jsonwebtoken::encode(&self.header, &claims, &self.encoding_key)
      .map_err(Error::from)
      .map_err(napi::Error::from)
  }

  #[napi]
  pub fn sign_claims(&self, claims: &Claims) -> napi::Result<String> {
    jsonwebtoken::encode(&self.header, claims, &self.encoding_key)
      .map_err(Error::from)
      .map_err(napi::Error::from)
  }

  #[napi]
  pub fn verify(&self, token: String) -> napi::Result<Claims> {
    jsonwebtoken::decode::<Claims>(&token, &self.decoding_key, &self.validation)
      .map(|c| c.claims)
      .map_err(Error::from)
      .map_err(napi::Error::from)
  }
}
