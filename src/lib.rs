#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

mod ecdh_c {
    include!(concat!(env!("OUT_DIR"), "/tiny-ecdh.rs"));
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Keypair(pub [u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret() {
        unsafe {
            let alice = Keypair([0x01; 32]);
            let bob = Keypair([0x02; 32]);

            let mut alice_public = [0u8; 64];
            let mut alice_private = alice.0.clone();

            let alice_pub_ptr = alice_public.as_mut_ptr();
            let alice_priv_ptr = alice_private.as_mut_ptr();

            let success = super::ecdh_c::ecdh_generate_keys(alice_pub_ptr, alice_priv_ptr);
            assert_eq!(
                success, 1,
                "ecdh_c::ecdh_generate_keys failed returned non-zero value for alice"
            );

            let mut bob_public = [0u8; 64];
            let mut bob_private = bob.0.clone();

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

            assert_eq!(1, super::ecdh_c::ecdh_shared_secret(alice_priv_ptr, bob_pub_ptr, alice_shared_key_ptr));
            assert_eq!(1, super::ecdh_c::ecdh_shared_secret(bob_priv_ptr, alice_pub_ptr, bob_shared_key_ptr));

            assert_eq!(alice_shared_key, bob_shared_key);
        }
    }
}
