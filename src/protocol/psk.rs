use std::sync::Arc;

use zeroize::Zeroizing;

use crate::protocol::v6::V6Profile;

#[derive(Clone)]
pub(crate) struct SnellPsk {
    inner: Arc<SnellPskInner>,
}

struct SnellPskInner {
    bytes: Zeroizing<Vec<u8>>,
    v6_profile: V6Profile,
}

impl SnellPsk {
    pub(crate) fn new(psk: Zeroizing<Vec<u8>>) -> Self {
        let v6_profile = V6Profile::derive(psk.as_slice());
        Self {
            inner: Arc::new(SnellPskInner {
                bytes: psk,
                v6_profile,
            }),
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.inner.bytes.as_slice()
    }

    pub(crate) fn v6_profile(&self) -> &V6Profile {
        &self.inner.v6_profile
    }
}
