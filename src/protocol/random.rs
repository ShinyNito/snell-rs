use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{Error, Result};

pub(crate) fn fill_random(buffer: &mut [u8]) -> Result<()> {
    SystemRandom::new().fill(buffer).map_err(|_| Error::Random)
}
