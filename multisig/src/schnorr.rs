extern crate rand;
extern crate rand_core;
extern crate rand_chacha;

use rand::{SeedableRng};
use rand_chacha::ChaChaRng;
use sha2::{Sha256, Digest};

#[derive(Clone)]
pub struct CommonParameters {
    context: schnorrkel::context::SigningContext,
}

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    public_key: schnorrkel::keys::PublicKey,
}

pub struct Signature {
    signature: schnorrkel::Signature,
}

///signing requires KeyPair (not just private key)
pub struct KeyPair {
    key_pair: schnorrkel::Keypair,
}

#[derive(Debug)]
pub struct Error(String);

fn to_message(message: &str) -> [u8;32] {
    let mut hasher = Sha256::default();
    let byte_message = message.as_bytes();
    hasher.input(byte_message);
    let output = hasher.result();
    const DIGEST_LENGTH: usize = 32;
    let mut converted_digest = [0u8; DIGEST_LENGTH];
    for i in 0..DIGEST_LENGTH {
        converted_digest[i] = output[i];
    }
    converted_digest
}

pub fn initialize(context_string: &str) -> CommonParameters {
    let context = schnorrkel::signing_context(context_string.as_bytes());
    CommonParameters{context}
}

pub fn generate_key_pair() -> Result<KeyPair, Error> {
    let csprng = ChaChaRng::from_seed([0u8; 32]);
    let key_pair = schnorrkel::Keypair::generate_with(csprng);
    Ok(KeyPair{key_pair})
}

pub fn sign(message: &str, key_pair: &KeyPair, common_parameters: &CommonParameters) -> Result<Signature, Error> {
//    let message_as_bytes = message.as_bytes();
    let message_input = to_message(message);
    let signature = key_pair.key_pair.sign(common_parameters.context.bytes(&message_input));
    Ok(Signature{signature})
}

pub fn verify_with_key_pair(message: &str, signature: &Signature, key_pair: &KeyPair,
              common_parameters: &CommonParameters) -> bool {
    let message_input = to_message(message);
    key_pair.key_pair.verify(
        common_parameters.context.bytes(&message_input), &signature.signature).is_ok()
}

pub fn key_pair_to_public_key(key_pair: &KeyPair) -> PublicKey {
    let public_key = key_pair.key_pair.public;
    PublicKey{public_key}
}

pub fn verify_with_public_key(message: &str, signature: &Signature, public_key: &PublicKey,
                              common_parameters: &CommonParameters) -> bool {
    let message_input = to_message(message);
    public_key.public_key.verify(
        common_parameters.context.bytes(&message_input), &signature.signature).is_ok()
}

#[test]
fn test_sign_and_verify_short_message_with_public_key() {
    let common_parameters = initialize("this thing");
    let message = "hello world";
    let key_pair = generate_key_pair().unwrap();
    let signature = sign(message, &key_pair, &common_parameters).unwrap();
    let public_key = key_pair_to_public_key(&key_pair);
    assert!(verify_with_public_key(message, &signature, &public_key, &common_parameters));
}

#[test]
fn test_sign_and_verify_long_message_with_public_key() {
    let common_parameters = initialize("this thing");
    let message = "hello from the other side i must have called a thousand times";
    let key_pair = generate_key_pair().unwrap();
    let signature = sign(message, &key_pair, &common_parameters).unwrap();
    let public_key = key_pair_to_public_key(&key_pair);
    assert!(verify_with_public_key(message, &signature, &public_key, &common_parameters));
}

#[test]
fn test_sign_and_verify_short_message_with_key_pair() {
    let common_parameters = initialize("this thing");
    let message = "hello world";
    let key_pair = generate_key_pair().unwrap();
    let signature = sign(message, &key_pair, &common_parameters).unwrap();
    assert!(verify_with_key_pair(message, &signature, &key_pair, &common_parameters));
}

#[test]
fn test_sign_and_verify_long_message_with_key_pair() {
    let common_parameters = initialize("this thing");
    let message = "hello from the other side i must have called a thousand times";
    let key_pair = generate_key_pair().unwrap();
    let signature = sign(message, &key_pair, &common_parameters).unwrap();
    assert!(verify_with_key_pair(message, &signature, &key_pair, &common_parameters));
}
