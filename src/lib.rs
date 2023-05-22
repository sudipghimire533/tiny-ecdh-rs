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
pub struct Keypair {
    private: PrivateKey,
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

    pub fn generate_shared_key(&self, others: PublicKey) -> Option<Keypair> {
        let mut shared_key = [0u8; 32];
        let res = unsafe {
            ecdh_c::ecdh_shared_secret(
                self.private.as_ptr(),
                others.as_ptr(),
                shared_key.as_mut_ptr(),
            )
        };

        if res == 1 {
            Self::new(shared_key)
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
        unsafe {
            let alice = Keypair::new([0x01; 32]).unwrap();
            let bob = Keypair::new([0x02; 32]).unwrap();

            let mut alice_public = [0u8; 64];
            let mut alice_private = alice.private().clone();

            let alice_pub_ptr = alice_public.as_mut_ptr();
            let alice_priv_ptr = alice_private.as_mut_ptr();

            let success = super::ecdh_c::ecdh_generate_keys(alice_pub_ptr, alice_priv_ptr);
            assert_eq!(
                success, 1,
                "ecdh_c::ecdh_generate_keys failed returned non-zero value for alice"
            );

            let mut bob_public = [0u8; 64];
            let mut bob_private = bob.private().clone();

            let bob_pub_ptr = bob_public.as_mut_ptr();
            let bob_priv_ptr = bob_private.as_mut_ptr();

            let success = super::ecdh_c::ecdh_generate_keys(bob_pub_ptr, bob_priv_ptr);
            assert_eq!(
                success, 1,
                "ecdh_c::ecdh_generate_keys failed returned non-zero value for bob"
            );

            let mut alice_shared_key = [0u8; 64];
            let mut bob_shared_key = [0u8; 64];
            let alice_shared_key_ptr = alice_shared_key.as_mut_ptr();
            let bob_shared_key_ptr = bob_shared_key.as_mut_ptr();

            assert_eq!(
                1,
                super::ecdh_c::ecdh_shared_secret(
                    alice_priv_ptr,
                    bob_pub_ptr,
                    alice_shared_key_ptr
                )
            );
            assert_eq!(
                1,
                super::ecdh_c::ecdh_shared_secret(bob_priv_ptr, alice_pub_ptr, bob_shared_key_ptr)
            );

            assert_eq!(alice_shared_key, bob_shared_key);
        }
    }
}
