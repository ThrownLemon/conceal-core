//! Adversarial edge-case tests — probing inputs the unit tests don't cover.

#[cfg(test)]
mod adversarial_edge_cases {
    use crate::raptor::*;
    use crate::falcon_ffi as fc;

    #[test]
    fn all_zero_members_rejected() {
        let (pk, _) = keygen(b"zero-test");
        let ring = vec![pk.a0];
        let sig = Signature {
            members: vec![Member { r0: [0i16; fc::N], r1: [0i16; fc::N], b: [0u8; 32] }],
            aots: [0u16; fc::N],
            ots_sig: OtsSig { s0: [0i16; fc::N], s1: [0i16; fc::N] },
        };
        assert!(verify(b"msg", &ring, &sig).is_err());
    }

    #[test]
    fn duplicate_ring_members_handled() {
        let (pk, sk) = keygen(b"dup-test");
        let ring = vec![pk.a0, pk.a0];
        if let Ok(s) = sign(b"msg", &ring, &sk, 0, &[0u8; 32]) {
            let _ = verify(b"msg", &ring, &s);
        }
    }

    #[test]
    fn zero_aots_rejected_in_forgery() {
        let (pk, _) = keygen(b"zero-aots-test");
        let ring = vec![pk.a0];
        let sig = Signature {
            members: vec![Member { r0: [0i16; fc::N], r1: [0i16; fc::N], b: [0u8; 32] }],
            aots: [0u16; fc::N],
            ots_sig: OtsSig { s0: [0i16; fc::N], s1: [0i16; fc::N] },
        };
        assert!(verify(b"msg", &ring, &sig).is_err());
    }

    #[test]
    fn signature_not_malleable_via_b() {
        let (pk, sk) = keygen(b"malleability-test");
        let ring = vec![pk.a0, pk.a0];
        let sig = sign(b"msg", &ring, &sk, 0, &[42u8; 32]).unwrap();
        let mut tampered = sig.clone();
        tampered.members[0].b[0] ^= 0x01;
        assert!(verify(b"msg", &ring, &tampered).is_err());
    }

    #[test]
    fn ring_size_1_verifies() {
        let (pk, sk) = keygen(b"ring1-test");
        let ring = vec![pk.a0];
        let sig = sign(b"msg", &ring, &sk, 0, &[99u8; 32]).unwrap();
        assert!(verify(b"msg", &ring, &sig).is_ok());
    }

    #[test]
    fn ring_size_32_verifies() {
        let (pk, sk) = keygen(b"ring32-test");
        let ring = vec![pk.a0; 32];
        let sig = sign(b"msg", &ring, &sk, 0, &[7u8; 32]).unwrap();
        assert!(verify(b"msg", &ring, &sig).is_ok());
    }

    #[test]
    fn wrong_message_rejected() {
        let (pk, sk) = keygen(b"wrongmsg-test");
        let ring = vec![pk.a0];
        let sig = sign(b"msg1", &ring, &sk, 0, &[0u8; 32]).unwrap();
        assert!(verify(b"msg2", &ring, &sig).is_err());
    }

    #[test]
    fn reordered_ring_rejected() {
        let (pk1, sk1) = keygen(b"reorder-1");
        let (pk2, _) = keygen(b"reorder-2");
        let ring = vec![pk1.a0, pk2.a0];
        let sig = sign(b"msg", &ring, &sk1, 0, &[0u8; 32]).unwrap();
        assert!(verify(b"msg", &ring, &sig).is_ok());
        let swapped = vec![pk2.a0, pk1.a0];
        assert!(verify(b"msg", &swapped, &sig).is_err());
    }

    #[test]
    fn nullifier_is_deterministic_and_consistent() {
        let (_, sk) = keygen(b"nf-test");
        let nf1 = nullifier(&sk);
        let nf2 = nullifier(&sk);
        assert_eq!(nf1, nf2);
        let (_, sk2) = keygen(b"nf-test-2");
        let nf3 = nullifier(&sk2);
        assert_ne!(nf1, nf3);
    }

    #[test]
    fn ots_replay_across_messages_rejected() {
        let (pk, sk) = keygen(b"ots-replay");
        let ring = vec![pk.a0];
        let sig1 = sign(b"msg1", &ring, &sk, 0, &[0u8; 32]).unwrap();
        assert!(verify(b"msg2", &ring, &sig1).is_err());
    }
}
