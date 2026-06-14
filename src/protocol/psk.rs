use std::sync::Arc;

use zeroize::Zeroizing;

use crate::protocol::v6::{SharedV6Profile, V6Profile};

#[derive(Clone)]
pub(crate) struct SnellPsk {
    bytes: Arc<Zeroizing<Vec<u8>>>,
    v6_profile: SharedV6Profile,
}

impl SnellPsk {
    pub(crate) fn new(psk: Zeroizing<Vec<u8>>) -> Self {
        let bytes = Arc::new(psk);
        let v6_profile = Arc::new(V6Profile::derive(bytes.as_slice()));
        Self { bytes, v6_profile }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub(crate) fn clone_v6_profile(&self) -> SharedV6Profile {
        self.v6_profile.clone()
    }
}
