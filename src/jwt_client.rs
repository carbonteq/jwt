use std::time::Duration;

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

#[inline]
fn get_header_validation(
  opts: Option<JwtClientInitOpts>,
) -> (jsonwebtoken::Header, jsonwebtoken::Validation) {
  let opts = opts.unwrap_or_default();
  let header: jsonwebtoken::Header = opts.header.unwrap_or_default().into();
  let validation = opts
    .validation
    .unwrap_or_default()
    .for_jsonwebtoken(header.alg);

  (header, validation)
}

#[inline]
fn get_symmetric_keys(
  secret_key: Either<String, Buffer>,
  alg: jsonwebtoken::Algorithm,
) -> Result<(jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey), Error> {
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

  Ok((encoding_key, decoding_key))
}

#[inline]
fn get_asymmetric_keys(
  alg: jsonwebtoken::Algorithm,
  pub_k: Either<String, Buffer>,
  priv_k: Either<String, Buffer>,
) -> Result<(jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey), Error> {
  let encoding_key = match priv_k {
    Either::A(s) => get_encoding_key(s.as_bytes(), alg),
    Either::B(buff) => get_encoding_key(&buff, alg),
  }?;

  let decoding_key = match pub_k {
    Either::A(s) => get_decoding_key(s.as_bytes(), alg),
    Either::B(buff) => get_decoding_key(&buff, alg),
  }?;

  Ok((encoding_key, decoding_key))
}

#[inline]
fn sign_claims(
  header: &jsonwebtoken::Header,
  enc_key: &jsonwebtoken::EncodingKey,
  claims: &Claims,
) -> Result<String, Error> {
  jsonwebtoken::encode(header, &claims, enc_key).map_err(Error::from)
}

#[inline]
fn verify_and_decode(
  token: &str,
  dec_key: &jsonwebtoken::DecodingKey,
  valid: &jsonwebtoken::Validation,
) -> Result<Claims, Error> {
  jsonwebtoken::decode::<Claims>(token, dec_key, valid)
    .map(|c| c.claims)
    .map_err(Error::from)
}

#[napi]
impl JwtClient {
  #[napi(constructor)]
  /// For symetric key based signatures
  pub fn new(
    secret_key: Either<String, Buffer>,
    opts: Option<JwtClientInitOpts>,
  ) -> Result<Self, Error> {
    let (header, validation) = get_header_validation(opts);
    let (encoding_key, decoding_key) = get_symmetric_keys(secret_key, header.alg)?;

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
    let (header, validation) = get_header_validation(opts);
    let (encoding_key, decoding_key) = get_asymmetric_keys(header.alg, pub_key, priv_key)?;

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
    let tok = sign_claims(&self.header, &self.encoding_key, &claims)?;
    Ok(tok)
  }

  #[napi]
  pub fn sign_claims(&self, claims: &Claims) -> napi::Result<String> {
    let tok = sign_claims(&self.header, &self.encoding_key, claims)?;
    Ok(tok)
  }

  #[napi]
  pub fn verify(&self, token: String) -> napi::Result<Claims> {
    let claims = verify_and_decode(&token, &self.decoding_key, &self.validation)?;
    Ok(claims)
  }

  #[napi(getter)]
  pub fn header(&self) -> Header {
    (&self.header).into()
  }
}

#[napi]
pub struct JwtCacheClient {
  encoding_key: jsonwebtoken::EncodingKey,
  decoding_key: jsonwebtoken::DecodingKey,
  header: jsonwebtoken::Header,
  validation: jsonwebtoken::Validation,
  cache: mini_moka::unsync::Cache<String, Claims>,
  ttl_secs: u32,
  max_capacity: u32,
}

#[napi]
impl JwtCacheClient {
  #[napi(constructor)]
  pub fn new(
    secret_key: Either<String, Buffer>,
    ttl_secs: u32,
    max_capacity: u32,
    opts: Option<JwtClientInitOpts>,
  ) -> Result<Self, Error> {
    let cache = mini_moka::unsync::Cache::builder()
      .max_capacity(u64::from(max_capacity))
      .time_to_live(Duration::from_secs(u64::from(ttl_secs)))
      .build();

    let (header, validation) = get_header_validation(opts);
    let (encoding_key, decoding_key) = get_symmetric_keys(secret_key, header.alg)?;

    Ok(Self {
      header,
      validation,
      encoding_key,
      decoding_key,
      cache,
      ttl_secs,
      max_capacity,
    })
  }

  #[napi(factory)]
  pub fn with_pub_priv_keys(
    pub_key: Either<String, Buffer>,
    priv_key: Either<String, Buffer>,
    ttl_secs: u32,
    max_capacity: u32,
    opts: Option<JwtClientInitOpts>,
  ) -> Result<Self, Error> {
    let cache = mini_moka::unsync::Cache::builder()
      .max_capacity(u64::from(max_capacity))
      .time_to_live(Duration::from_secs(u64::from(ttl_secs)))
      .build();

    let (header, validation) = get_header_validation(opts);
    let (encoding_key, decoding_key) = get_asymmetric_keys(header.alg, pub_key, priv_key)?;

    Ok(Self {
      header,
      validation,
      encoding_key,
      decoding_key,
      cache,
      ttl_secs,
      max_capacity,
    })
  }

  #[napi]
  pub fn sign(
    &self,
    data: serde_json::Map<String, serde_json::Value>,
    claim_opts: Option<ClaimOpts>,
  ) -> napi::Result<String> {
    let claims = Claims::new(data, self.ttl_secs, claim_opts);
    let tok = sign_claims(&self.header, &self.encoding_key, &claims)?;
    Ok(tok)
  }

  #[napi]
  pub fn verify(&mut self, token: String) -> napi::Result<Claims> {
    let claims = match self.cache.get(&token) {
      Some(c) => c.to_owned(),
      None => {
        let claims = verify_and_decode(&token, &self.decoding_key, &self.validation)?;
        self.cache.insert(token, claims.clone());
        claims
      }
    };

    Ok(claims)
  }

  #[napi]
  pub fn invalidate_cache(&mut self) {
    self.cache.invalidate_all();
  }

  #[napi(getter)]
  pub fn header(&self) -> Header {
    (&self.header).into()
  }

  #[napi(getter)]
  pub fn ttl_secs(&self) -> u32 {
    self.ttl_secs
  }

  #[napi(getter)]
  pub fn max_capacity(&self) -> u32 {
    self.max_capacity
  }
}
