use std::time::SystemTime;

use hmac::{Hmac, Mac};

#[inline]
pub fn unix_epoch_sec() -> Option<u64> {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => Some(d.as_secs()),
        Err(_err) => None,
    }
}

#[derive(Debug, thiserror::Error)]
#[error("error generating unix timestamp")]
pub struct UnixTimestampError;

/// available hashs for generating codes
pub enum Algo {
    SHA1,
    SHA256,
    SHA512,
}

/// crates a single use hmac from the given [`Algo`] with the secret and data
#[inline]
fn one_off(algo: &Algo, secret: &[u8], data: &[u8]) -> Vec<u8> {
    match algo {
        Algo::SHA1 => {
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Algo::SHA256 => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Algo::SHA512 => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(secret).unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// simple string padding given a string and total digits
///
/// this will not truncate the string and will just return if the given string
/// is big enough or is equal to the given digits
fn pad_string(uint_string: String, digits: usize) -> String {
    if uint_string.len() < digits {
        let mut rtn = String::with_capacity(digits);

        for _ in 0..(digits - uint_string.len()) {
            rtn.push('0');
        }

        rtn.push_str(&uint_string);
        rtn
    } else {
        uint_string
    }
}

/// generate integer string for otp algorithms
///
/// creates the integer string for the given algorithm. will pad the string
/// if it is not long enough for the given amount of digits.
fn generate_integer_string(algorithm: &Algo, secret: &[u8], digits: u32, data: &[u8]) -> String {
    let hash = one_off(algorithm, secret, data);

    // pull in the offset from the last byte in the hash
    let offset = (hash[hash.len() - 1] & 0xf) as usize;
    // since we are only going to be filling 32 bits we can set it as a u32
    // and not have to worry overflow since a u32 consists of 4 u8's. casting
    // the u8's up should not be an issue
    let binary = ((hash[offset] & 0x7f) as u32) << 24
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | (hash[offset + 3] as u32);

    let uint_string = (binary % 10u32.pow(digits)).to_string();
    let digits = digits as usize;

    pad_string(uint_string, digits)
}

/// create a hotp code
pub fn hotp<S>(secret: S, digits: u32, counter: u64) -> String
where
    S: AsRef<[u8]>,
{
    let counter_bytes = counter.to_be_bytes();

    generate_integer_string(&Algo::SHA1, secret.as_ref(), digits, &counter_bytes)
}

/// create a totp code
///
/// see [`Error`](crate::error::Error) for potential errors
pub fn totp<S>(algorithm: &Algo, secret: S, digits: u32, step: u64, time: u64) -> String
where
    S: AsRef<[u8]>,
{
    let data = (time / step).to_be_bytes();

    generate_integer_string(algorithm, secret.as_ref(), digits, &data)
}

/// result from totp verification
pub enum VerifyResult {
    /// provided code is valid
    Valid,
    /// provided code is invalid
    Invalid,
    /// code contains a non acii digit
    InvalidCharacters,
    /// code is not the required length
    InvalidLength,
}

/// settings for totp verification
pub struct TotpSettings {
    /// desired algorithm to use. see [`Algo`]
    pub algo: Algo,
    /// total digits to generate codes with
    pub digits: u32,
    /// timestamp steps
    pub step: u64,
    /// total increments to check before `now`
    pub window_before: u8,
    /// total increments to check after `now`
    pub window_after: u8,
    /// prespecified `now`. if none is provided it will pull the current
    /// UNIX_EPOCH value in seconds
    pub now: Option<u64>,
}

impl Default for TotpSettings {
    fn default() -> Self {
        Self {
            algo: Algo::SHA256,
            digits: 6,
            step: 30,
            window_before: 1,
            window_after: 1,
            now: None,
        }
    }
}

/// verify totp code from given settings
///
/// checks to make sure that the code contains only ascii digits and that the
/// length is equal to the specified digits. after that the current timestamp
/// is checked first, then window before, then window after. if an overflow
/// happens when creating the window timpestamps a UnixTimestampeError is
/// returned.
pub fn verify_totp_code<S, C>(
    secret: S,
    code: C,
    settings: &TotpSettings,
) -> Result<VerifyResult, UnixTimestampError>
where
    S: AsRef<[u8]>,
    C: AsRef<str>,
{
    let code_ref = code.as_ref();
    let mut len: u32 = 0;

    for ch in code_ref.chars() {
        if !ch.is_ascii_digit() {
            return Ok(VerifyResult::InvalidCharacters);
        }

        len += 1;
    }

    if len != settings.digits {
        return Ok(VerifyResult::InvalidLength);
    }

    let now = match settings.now {
        Some(given) => given,
        None => unix_epoch_sec().ok_or(UnixTimestampError)?,
    };

    // check now first
    if totp(&settings.algo, &secret, settings.digits, settings.step, now) == code_ref {
        return Ok(VerifyResult::Valid);
    }

    // check before now
    for win in 1..=settings.window_before {
        let value = settings.step * (win as u64);
        let time = now.checked_sub(value).ok_or(UnixTimestampError)?;

        if totp(
            &settings.algo,
            &secret,
            settings.digits,
            settings.step,
            time,
        ) == code_ref
        {
            return Ok(VerifyResult::Valid);
        }
    }

    // check after now
    for win in 1..=settings.window_after {
        let value = settings.step * (win as u64);
        let time = now.checked_add(value).ok_or(UnixTimestampError)?;

        if totp(
            &settings.algo,
            &secret,
            settings.digits,
            settings.step,
            time,
        ) == code_ref
        {
            return Ok(VerifyResult::Valid);
        }
    }

    Ok(VerifyResult::Invalid)
}

#[cfg(test)]
mod test {
    use super::*;

    const DEFAULT_STEP: u64 = 30;
    const DEFAULT_DIGITS: u32 = 8;

    #[test]
    fn htop_test() {
        let secret = b"12345678901234567890";
        let results = vec![
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for count in 0..results.len() {
            let check = hotp(secret, 6, count as u64);

            assert_eq!(
                check.as_str(),
                results[count],
                "count: {} received: {} expected: {}",
                count,
                check,
                results[count]
            );
        }
    }

    #[test]
    fn totp_sha1_test() {
        let secret = b"12345678901234567890";

        let pairs = vec![
            ("94287082", 59),
            ("07081804", 1111111109),
            ("14050471", 1111111111),
            ("89005924", 1234567890),
            ("69279037", 2000000000),
            ("65353130", 20000000000),
        ];

        for (expected, time) in pairs {
            let check = totp(&Algo::SHA1, secret, DEFAULT_DIGITS, DEFAULT_STEP, time);

            assert_eq!(
                check.as_str(),
                expected,
                "time: {time} check: {check} expected: {expected}",
            );
        }
    }

    #[test]
    fn totp_sha256_test() {
        let secret = b"12345678901234567890123456789012";

        let pairs = vec![
            ("46119246", 59),
            ("68084774", 1111111109),
            ("67062674", 1111111111),
            ("91819424", 1234567890),
            ("90698825", 2000000000),
            ("77737706", 20000000000),
        ];

        for (expected, time) in pairs {
            let check = totp(&Algo::SHA256, secret, DEFAULT_DIGITS, DEFAULT_STEP, time);

            assert_eq!(
                check.as_str(),
                expected,
                "time: {time} check: {check} expected: {expected}",
            );
        }
    }

    #[test]
    fn totp_sha512_test() {
        let secret = b"1234567890123456789012345678901234567890123456789012345678901234";

        let pairs = vec![
            ("90693936", 59),
            ("25091201", 1111111109),
            ("99943326", 1111111111),
            ("93441116", 1234567890),
            ("38618901", 2000000000),
            ("47863826", 20000000000),
        ];

        for (expected, time) in pairs {
            let check = totp(&Algo::SHA512, secret, DEFAULT_DIGITS, DEFAULT_STEP, time);

            assert_eq!(
                check.as_str(),
                expected,
                "time: {time} check: {check} expected: {expected}",
            );
        }
    }
}
