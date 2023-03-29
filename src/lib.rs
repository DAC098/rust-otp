pub mod error;

mod otp;
mod time;

pub use otp::{
    Algo,
    VerifyResult,
    TotpSettings,
    try_hotp,
    try_totp,
    hotp,
    totp,
    verify_totp_code,
};
