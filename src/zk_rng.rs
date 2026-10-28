//! `ZkRng`: OS-seeded CSPRNG for the hiding PCS and the LogUp masks; `Clone` reseeds from the OS.

use core::convert::Infallible;

use rand::rngs::{StdRng, SysRng};
use rand::{SeedableRng, TryCryptoRng, TryRng};

/// OS-seeded CSPRNG whose `Clone` draws a fresh OS seed.
pub struct ZkRng(StdRng);

impl ZkRng {
    /// A fresh generator seeded from the operating system.
    ///
    /// Panics if the OS entropy source fails: there is no safe fallback for
    /// a mask RNG.
    pub fn from_os() -> Self {
        Self(StdRng::try_from_rng(&mut SysRng).expect("OS entropy source failed (ZkRng)"))
    }
}

impl Clone for ZkRng {
    /// Reseeds from the OS: a clone must never replay the original's stream.
    fn clone(&self) -> Self {
        Self::from_os()
    }
}

impl core::fmt::Debug for ZkRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ZkRng(os-seeded)")
    }
}

impl TryRng for ZkRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.try_fill_bytes(dst)
    }
}

impl TryCryptoRng for ZkRng {}

#[cfg(test)]
mod tests {
    use rand::{CryptoRng, Rng};

    use super::ZkRng;

    fn assert_pcs_bounds<R: CryptoRng + Clone + Send + Sync>() {}

    #[test]
    fn clone_reseeds_instead_of_copying() {
        assert_pcs_bounds::<ZkRng>();
        let mut a = ZkRng::from_os();
        let mut b = a.clone();
        let (xa, xb): (Vec<u64>, Vec<u64>) = (0..4).map(|_| (a.next_u64(), b.next_u64())).unzip();
        assert_ne!(xa, xb, "a clone replayed the original's stream");
        let mut c = ZkRng::from_os();
        assert_ne!((0..4).map(|_| c.next_u64()).collect::<Vec<_>>(), xa);
        assert_eq!(format!("{a:?}"), "ZkRng(os-seeded)");
    }
}
