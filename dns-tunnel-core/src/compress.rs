//! Optional payload compression (ADR 0011 §6): LZ4 via `lz4_flex` (pure Rust — deliberately not the
//! C-backed `zstd` crate). Compress only when it helps (payload large enough AND the compressed form
//! is strictly smaller); a decompressed-size cap, checked against the length prefix *before*
//! allocating, guards against decompression bombs. Off by default at the config level.

/// `comp_algo` value: payload is uncompressed.
pub const ALGO_NONE: u8 = 0;
/// `comp_algo` value: payload is LZ4 (block, 4-byte little-endian size prefix).
pub const ALGO_LZ4: u8 = 1;

/// Default minimum payload size before attempting compression (small payloads rarely shrink).
pub const DEFAULT_MIN_SIZE: usize = 96;
/// Hard cap on decompressed output — rejects a forged size prefix before it can allocate.
pub const MAX_DECOMPRESSED: usize = 1 << 20; // 1 MiB

/// Compression errors.
#[derive(Debug, thiserror::Error)]
pub enum CompressError {
    /// LZ4 decompression failed (corrupt input or bad size prefix).
    #[error("lz4 decompression failed")]
    Lz4,
    /// The claimed/decompressed size exceeds [`MAX_DECOMPRESSED`].
    #[error("decompressed size {0} exceeds cap")]
    TooLarge(usize),
    /// The `comp_algo` value is not one we know.
    #[error("unknown compression algorithm {0}")]
    UnknownAlgo(u8),
}

/// Try to LZ4-compress `payload`. Returns `Some(compressed)` only if `payload.len() >= min_size` and
/// the compressed form is strictly smaller; otherwise `None` (the caller sends it uncompressed with
/// `comp_algo = ALGO_NONE`).
pub fn maybe_compress(payload: &[u8], min_size: usize) -> Option<Vec<u8>> {
    if payload.len() < min_size {
        return None;
    }
    let compressed = lz4_flex::compress_prepend_size(payload);
    (compressed.len() < payload.len()).then_some(compressed)
}

/// Decompress `data` that was produced under `algo`. `ALGO_NONE` copies the input through.
pub fn decompress(algo: u8, data: &[u8]) -> Result<Vec<u8>, CompressError> {
    match algo {
        ALGO_NONE => Ok(data.to_vec()),
        ALGO_LZ4 => {
            // Reject a forged size prefix before `lz4_flex` allocates it (anti-bomb).
            let prefix: [u8; 4] = data.get(..4).ok_or(CompressError::Lz4)?.try_into().unwrap();
            let claimed = u32::from_le_bytes(prefix) as usize;
            if claimed > MAX_DECOMPRESSED {
                return Err(CompressError::TooLarge(claimed));
            }
            lz4_flex::decompress_size_prepended(data).map_err(|_| CompressError::Lz4)
        }
        other => Err(CompressError::UnknownAlgo(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressible_payload_round_trips() {
        let payload = vec![0xABu8; 4096]; // highly compressible
        let c = maybe_compress(&payload, DEFAULT_MIN_SIZE).expect("should compress");
        assert!(c.len() < payload.len());
        assert_eq!(decompress(ALGO_LZ4, &c).unwrap(), payload);
    }

    #[test]
    fn tiny_or_incompressible_returns_none() {
        // Below the threshold.
        assert!(maybe_compress(&[1, 2, 3], DEFAULT_MIN_SIZE).is_none());
        // Incompressible (pseudo-random) data does not shrink.
        let mut s = 0x1234_5678_9abc_def0u64;
        let random: Vec<u8> = (0..1024)
            .map(|_| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                (s >> 33) as u8
            })
            .collect();
        assert!(maybe_compress(&random, DEFAULT_MIN_SIZE).is_none());
    }

    #[test]
    fn algo_none_passes_through() {
        assert_eq!(decompress(ALGO_NONE, b"raw").unwrap(), b"raw");
    }

    #[test]
    fn decompress_rejects_bomb_unknown_and_garbage() {
        // Forged size prefix claiming 2 MiB → rejected before allocating.
        let mut bomb = (2u32 * 1024 * 1024).to_le_bytes().to_vec();
        bomb.extend_from_slice(&[0u8; 8]);
        assert!(matches!(
            decompress(ALGO_LZ4, &bomb),
            Err(CompressError::TooLarge(_))
        ));
        // Unknown algorithm.
        assert!(matches!(
            decompress(7, b"x"),
            Err(CompressError::UnknownAlgo(7))
        ));
        // Garbage LZ4 (valid small size prefix, corrupt body).
        let mut garbage = 16u32.to_le_bytes().to_vec();
        garbage.extend_from_slice(&[0xFF; 3]);
        assert!(matches!(
            decompress(ALGO_LZ4, &garbage),
            Err(CompressError::Lz4)
        ));
        // Too short for even a size prefix.
        assert!(matches!(
            decompress(ALGO_LZ4, &[1, 2]),
            Err(CompressError::Lz4)
        ));
    }
}
