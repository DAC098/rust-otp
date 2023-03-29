use std::time::SystemTime;

#[inline]
pub fn unix_epoch_sec() -> Option<u64> {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => Some(d.as_secs()),
        Err(_err) => None,
    }
}
