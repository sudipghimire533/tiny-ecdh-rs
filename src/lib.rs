#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub mod ecdh_c {
    include!(concat!(env!("OUT_DIR"), "/tiny-ecdh.rs"));
}

pub type PrivateKey = [u8; 32];
pub type PublicKey = [u8; 64];

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Keypair {
    private: PrivateKey,
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    public: PublicKey,
}

impl Keypair {
    pub fn new(private: PrivateKey) -> Option<Self> {
        let mut private = private.to_vec();
        let mut public = [0; 64].to_vec();

        let private_ref = private.as_mut_ptr();
        let public_ref = public.as_mut_ptr();

        let generate_res = unsafe { ecdh_c::ecdh_generate_keys(public_ref, private_ref) };

        if generate_res == 1 {
            match (public.try_into(), private.try_into()) {
                (Ok(public), Ok(private)) => Some(Self { private, public }),
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn generate_shared_key(&self, others: PublicKey) -> Option<PublicKey> {
        let mut shared_key = [0u8; 64];
        let res = unsafe {
            ecdh_c::ecdh_shared_secret(
                self.private.as_ptr(),
                others.as_ptr(),
                shared_key.as_mut_ptr(),
            )
        };

        if res == 1 {
            Some(shared_key)
        } else {
            None
        }
    }

    pub fn private(&self) -> &PrivateKey {
        &self.private
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    pub fn inner(self) -> (PublicKey, PrivateKey) {
        (self.public, self.private)
    }
}

impl TryFrom<PrivateKey> for Keypair {
    type Error = &'static str;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        let pair = Self::new(value).ok_or("Cannot construct keypair")?;
        Ok(pair)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation() {
        let alice_expected = Keypair {
            private: [
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                0x01, 0x00, 0x00, 0x00,
            ],
            public: [
                0xF5, 0xDD, 0xD2, 0xC7, 0x04, 0x92, 0xE0, 0xD6, 0xF2, 0x1F, 0x8D, 0xEC, 0xE0, 0x2D,
                0x0A, 0xAF, 0x75, 0x64, 0x78, 0xE1, 0x02, 0x09, 0x72, 0x75, 0x19, 0x5A, 0xFB, 0x9B,
                0xB8, 0x01, 0x00, 0x00, 0xB3, 0x29, 0x00, 0x02, 0x9A, 0xB4, 0xD6, 0x84, 0x1C, 0xC5,
                0x2B, 0x51, 0x72, 0xEE, 0x2F, 0x3C, 0x5A, 0x66, 0xBC, 0x6F, 0x03, 0x25, 0x3A, 0x92,
                0x43, 0x9E, 0x14, 0x2F, 0x82, 0x00, 0x00, 0x00,
            ],
        };

        let alice = Keypair::new([0x01; 32]).unwrap();
        assert_eq!(alice_expected, alice);
    }

    #[test]
    fn shared_secret() {
        let alice = Keypair::new([0x01; 32]).unwrap();
        let bob = Keypair::new([0x02; 32]).unwrap();

        let alice_shared_key = alice.generate_shared_key(bob.public().clone()).unwrap();
        let bob_shared_key = bob.generate_shared_key(alice.public().clone()).unwrap();

        let expected_shared_key = [
            0x57, 0x57, 0x3A, 0x81, 0xE2, 0x7E, 0x48, 0x26, 0xFA, 0x8E, 0x18, 0x70, 0xCD, 0x6B,
            0x66, 0x40, 0xF3, 0x90, 0x5D, 0x98, 0x40, 0xF4, 0x12, 0xFA, 0xAE, 0x74, 0x0B, 0x12,
            0xE0, 0x01, 0x00, 0x00, 0xC4, 0xD8, 0x27, 0xA9, 0x37, 0x49, 0xEE, 0x44, 0xEA, 0x1B,
            0xAC, 0x1C, 0x18, 0x8C, 0x03, 0xAA, 0x6B, 0x02, 0xDA, 0x1C, 0x68, 0xE9, 0xE8, 0xE6,
            0xCA, 0xB9, 0xD1, 0xED, 0x91, 0x01, 0x00, 0x00,
        ];

        assert_eq!(alice_shared_key, bob_shared_key);
        assert_eq!(alice_shared_key, expected_shared_key);
    }

    #[test]
    fn reconstruct() {
        let alice = Keypair::new([0x01; 32]).unwrap();
        let re_alice = Keypair::new(alice.private().clone()).unwrap();

        assert_eq!(alice, re_alice);
    }

    #[test]
    fn try_from_array() {
        let _alice: Keypair = [0x01; 32].try_into().unwrap();
    }
}
