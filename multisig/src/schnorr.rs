extern crate rand;
extern crate rand_core;
extern crate rand_chacha;

use rand::{Rng, os::OsRng, SeedableRng}; //i'm using OsRng
use rand_core::{CryptoRng, RngCore};
use rand_chacha::ChaChaRng; //behaves badly
//use schnorrkel::{Keypair,Signature,signing_context}; //write full name

//#[derive(Copy)]
pub struct CommonParameters {
    schnorrkel: schnorrkel::context::SigningContext,
//    rng: rand::os::OsRng,
    rng: ChaChaRng,
}

//impl CryptoRng for CommonParameters::rng {}

pub struct PrivateKey {
    private_key: schnorrkel::keys::SecretKey,
}

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    public_key: schnorrkel::keys::PublicKey,
}

pub struct Signature {
    signature: schnorrkel::Signature,
}

pub struct KeyPair {
    key_pair: schnorrkel::Keypair,
}

#[derive(Debug)]
pub struct Error(String);

pub fn initialize() -> CommonParameters {
    let schnorrkel = schnorrkel::signing_context(b"this signature does this thing");
    let csprng = ChaChaRng::from_seed([0u8; 32]); //apparently dont need mutable
    CommonParameters{schnorrkel, rng: csprng}
}

//pub fn generate_key_pair(common_parameters: &mut CommonParameters) -> (PublicKey, PrivateKey) {
//    let mut csprng = rand::os::OsRng::new().unwrap();
//    let private_key = schnorrkel::SecretKey::generate_with(&mut csprng);
//    let public_key = schnorrkel::SecretKey::to_public(&private_key);
//    (PublicKey{public_key}, PrivateKey{private_key})
//}

//pub fn generate_key_pair(common_parameters: &mut CommonParameters) -> (PublicKey, PrivateKey) {
//    let mut csprng = ChaChaRng::from_seed([0u8; 32]);
//    let private_key = schnorrkel::SecretKey::generate_with(&mut csprng);
//    let public_key = schnorrkel::SecretKey::to_public(&private_key);
//    (PublicKey{public_key}, PrivateKey{private_key})
//}

pub fn generate_key_pair(common_parameters: CommonParameters) -> KeyPair {
    let key_pair = schnorrkel::Keypair::generate_with(common_parameters.rng);
    KeyPair{key_pair}
}

pub fn sign(message: &str, key_pair: &KeyPair, common_parameters: CommonParameters) -> Signature {
    //generate_key_pair(&mut common_parameters);
    let message_as_bytes = message.as_bytes();
    let signature = key_pair.key_pair.sign(common_parameters.schnorrkel.bytes(message_as_bytes));
    Signature{signature}
}

pub fn verify(message: &str, signature: &Signature, key_pair: &KeyPair,
              common_parameters: CommonParameters) -> bool {
    let message_as_bytes = message.as_bytes();
    key_pair.key_pair.verify(
        common_parameters.schnorrkel.bytes(message_as_bytes), &signature.signature).is_ok()
}

pub fn key_pair_to_public_key(key_pair: &KeyPair) -> PublicKey {
    let public_key = key_pair.key_pair.public;
    PublicKey{public_key}
}

pub fn verify_with_public_key(message: &str, signature: &Signature, public_key: &PublicKey,
                              common_parameters: CommonParameters) -> bool {
    let message_as_bytes = message.as_bytes();
    public_key.public_key.verify(
        common_parameters.schnorrkel.bytes(message_as_bytes), &signature.signature).is_ok()
}

//#[test]
//fn test_sign_and_verify_with_public_key() {
//    let mut common_parameters = initialize();
//    let common_parameters_copy_one = &common_parameters;
//    let common_parameters_copy_two = &common_parameters;
//    let common_parameters_copy_three = &common_parameters;
//    let message = "hello world";
//    let key_pair = generate_key_pair(common_parameters_copy_one);
//    let signature = sign(message, &key_pair, common_parameters_copy_two);
////    let public_key = key_pair_to_public_key(&key_pair);
////    assert!(verify_with_public_key(message, &signature, &public_key, common_parameters));
//}























//pub fn sign(message: &str, private_key: &PrivateKey) -> () {
//    let message_input = message.as_bytes();
//    let keypair = schnorrkel::SecretKey::to_keypair(private_key.private_key);
////    let signature = keypair.sign(schnorrkel::bytes(message_input));
////    Signature{signature}
//    schnorrkel::context::signing_context.bytes(message_input);
//}

//pub fn sign(message: &str, private_key: &PrivateKey) -> Signature {
//    let
//}








































