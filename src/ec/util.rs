use crate::{
    Ciphersuite,
    consts::ecvrf::{
        challenge::{ECVRF_CHAL_GEN_DST_BACK, ECVRF_CHAL_GEN_DST_FRONT},
        e2c::{ECVRF_E2C_DST_BACK, ECVRF_E2C_DST_FRONT},
        proof::{ECVRF_PROOF_DST_BACK, ECVRF_PROOF_DST_FRONT},
    },
};

pub(crate) fn encode_to_curve_tai_generator<H: digest::Digest>(
    suite: Ciphersuite,
    salt: &[u8],
    alpha: &[u8],
) -> impl Iterator<Item = digest::Output<H>> {
    // 1. ctr = 0
    let mut ctr = 0u8;
    std::iter::from_fn(move || {
        let next_ctr_value = ctr.checked_add(1)?;
        // hash_string = Hash(
        //   suite_string || encode_to_curve_domain_separator_front ||
        //   encode_to_curve_salt || alpha_string ||
        //   ctr_string || encode_to_curve_domain_separator_back
        // )
        let hash_string = H::new()
            .chain_update([*suite, ECVRF_E2C_DST_FRONT])
            .chain_update(salt)
            .chain_update(alpha)
            .chain_update([ctr, ECVRF_E2C_DST_BACK])
            .finalize();

        ctr = next_ctr_value;
        Some(hash_string)
    })
}

pub(crate) fn proof_to_hash<H: digest::Digest>(
    suite: Ciphersuite,
    gamma_string: &[u8],
) -> digest::Output<H> {
    H::new()
        .chain_update([*suite, ECVRF_PROOF_DST_FRONT])
        .chain_update(gamma_string)
        .chain_update([ECVRF_PROOF_DST_BACK])
        .finalize()
}

pub(crate) fn challenge_bytes<'a, const CHALLENGE_LEN: usize, H: digest::Digest>(
    suite: Ciphersuite,
    points: impl Iterator<Item = &'a [u8]>,
) -> zeroize::Zeroizing<[u8; CHALLENGE_LEN]> {
    let mut hasher = H::new();
    hasher.update([*suite, ECVRF_CHAL_GEN_DST_FRONT]);
    let mut point_count = 0u8;
    for point in points {
        hasher.update(point);
        point_count += 1;
    }
    debug_assert_eq!(point_count, 5, "Point count MUST be 5");
    hasher.update([ECVRF_CHAL_GEN_DST_BACK]);
    let c_string = hasher.finalize();

    zeroize::Zeroizing::new(c_string[..CHALLENGE_LEN].try_into().unwrap())
}
