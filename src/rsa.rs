pub trait RsaFdhVrf {
    type Hash: digest::Digest + digest::FixedOutputReset;
    fn ciphersuite() -> crate::Ciphersuite;

    fn mgf1(mgf_seed: &[u8], mask_len: usize) -> Option<Vec<u8>> {
        use digest::Digest as _;
        let h_len = <Self::Hash as digest::OutputSizeUser>::output_size();
        const MAX_LEN: u64 = u32::MAX as u64 + 1;

        // 1.  If maskLen > 2^32 hLen, output "mask too long" and stop.
        if mask_len as u64 > MAX_LEN {
            return None;
        }

        // 2.  Let T be the empty octet string.
        let ctr_target = mask_len.div_ceil(h_len);
        let mut big_t = Vec::with_capacity(ctr_target);

        let mut digest = Self::Hash::new();

        // 3.  For counter from 0 to \ceil (maskLen / hLen) - 1, do the following:
        let ctr_end = ctr_target as u32;
        for i in 0..ctr_end {
            //       A.  Convert counter to an octet string C of length 4 octets (see
            //           Section 4.1):
            //              C = I2OSP (counter, 4) .
            let big_c = i.to_be_bytes();

            //       B.  Concatenate the hash of the seed mgfSeed and C to the octet
            //           string T:
            //              T = T || Hash(mgfSeed || C) .
            digest.update(mgf_seed);
            digest.update(&big_c);

            big_t.append(&mut digest.finalize_reset().into_iter().collect());
        }

        Some(big_t)
    }
}
