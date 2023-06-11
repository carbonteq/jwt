#![deny(clippy::all)]

// DISCLAIMER: Majority of the code and/or inspiration comes from @node-rs/jsonwebtoken. I have
// just updated and modified the code to meet my own use cases and API design

mod claims;
mod jwt_client;

pub use claims::{ClaimOpts, Claims};
pub use jwt_client::JwtClient;
