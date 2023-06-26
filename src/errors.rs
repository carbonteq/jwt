pub enum Error {
  InvalidKey(String),
  TokenValidationFailed(String),
  Generic(String),
}

impl From<Error> for napi::Error {
  fn from(value: Error) -> Self {
    match value {
      Error::InvalidKey(e) => Self::new(napi::Status::InvalidArg, e),
      Error::TokenValidationFailed(e) => Self::new(napi::Status::GenericFailure, e),
      Error::Generic(msg) => Self::new(napi::Status::Unknown, msg),
    }
  }
}

impl From<jsonwebtoken::errors::Error> for Error {
  fn from(value: jsonwebtoken::errors::Error) -> Self {
    let msg = value.to_string();
    use jsonwebtoken::errors::ErrorKind;

    match value.kind() {
      ErrorKind::InvalidRsaKey(_) | ErrorKind::InvalidEcdsaKey | ErrorKind::InvalidKeyFormat => {
        Self::InvalidKey(msg)
      }
      ErrorKind::InvalidToken
      | ErrorKind::InvalidSignature
      | ErrorKind::ExpiredSignature
      | ErrorKind::InvalidIssuer
      | ErrorKind::MissingRequiredClaim(_)
      | ErrorKind::InvalidAlgorithm
      | ErrorKind::InvalidAudience
      | ErrorKind::InvalidSubject
      | ErrorKind::ImmatureSignature => Self::TokenValidationFailed(msg),
      _ => Self::Generic(msg),
    }
  }
}
