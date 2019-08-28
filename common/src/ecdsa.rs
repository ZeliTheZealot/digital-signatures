//! This crate wraps libsecp256k1. The message is a str and we use Sha256 for hashing.
//!
//! # Example
//!
//! Creating a signature on a message is simple.
//!
//! First, we need to initialise the crate and generate the key-pair which include the public key
//! and the private key.
//!
//! ```
//! use digital_signature::common::ecdsa::*;
//! fn main() {
//! let mut common_parameters = initialize();
//! let (public_key, private_key) = generate_key_pair(&mut common_parameters).unwrap();
//! }
//! ```
//!
//! We can now use the private key to sign our message str.
//!
//! ```
//! # use digital_signature::common::ecdsa::*;
//! # fn main() {
//! # let mut common_parameters = initialize();
//! # let (public_key, private_key) = generate_key_pair(&mut common_parameters).unwrap();
//! let message = "hello world";
//! let (signature, recovery_id) = sign(&message, &private_key).unwrap();
//! # }
//! ```
//!
//! To verify that the signature is valid for our message, we use the public key.
//!
//! ```
//! # use digital_signature::common::ecdsa::*;
//! # fn main() {
//! # let mut common_parameters = initialize();
//! # let (public_key, private_key) = generate_key_pair(&mut common_parameters).unwrap();
//! # let message = "hello world";
//! # let (signature, recovery_id) = sign(&message, &private_key).unwrap();
//! assert!(verify(&message, &signature, &public_key));
//! # }
//! ```
//!
//! Finally, we can recover the public key using the message and the output of the
//! signing function.
//!
//! ```
//! # use digital_signature::common::ecdsa::*;
//! # fn main() {
//! # let mut common_parameters = initialize();
//! # let (public_key, private_key) = generate_key_pair(&mut common_parameters).unwrap();
//! # let message = "hello world";
//! # let (signature, recovery_id) = sign(&message, &private_key).unwrap();
//! # assert!(verify(&message, &signature, &public_key));
//! assert_eq!(recover(&message, &signature, &recovery_id).unwrap(), public_key);
//! # }
//! ```

extern crate digest;
extern crate generic_array;
extern crate hmac_drbg;
extern crate rand;
extern crate secp256k1;
extern crate secp256k1_test;
extern crate sha2;
extern crate typenum;

use rand::ThreadRng;
use rand::thread_rng;
//use rand::prelude::ThreadRng;
//use rand::Rng;
use sha2::{Sha256, Digest};

pub struct CommonParameters {
    secp256k1: secp256k1_test::Secp256k1,
    rng: ThreadRng,
}

pub struct PrivateKey {
    private_key: secp256k1::SecretKey,
}

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    public_key: secp256k1::PublicKey,
}

pub struct Signature {
    signature: secp256k1::Signature,
}

pub struct RecoveryId {
    recovery_id: secp256k1::RecoveryId,
}

#[derive(Debug)]
pub struct Error(String);

fn from_secp256k1_error(error_enum: secp256k1::Error) -> Error {
    let result = match error_enum {
        secp256k1::Error::InvalidSignature=> "InvalidSignature",
        secp256k1::Error::InvalidPublicKey=> "InvalidPublicKey",
        secp256k1::Error::InvalidSecretKey=> "InvalidSecretKey",
        secp256k1::Error::InvalidRecoveryId=> "InvalidRecoveryId",
        secp256k1::Error::InvalidMessage=> "InvalidMessage",
        secp256k1::Error::InvalidInputLength=> "InvalidInputLength",
        secp256k1::Error::TweakOutOfRange=> "TweakOutOfRange",
    };
    Error(result.to_string())
}

fn from_secp256k1_test_error(error_enum: secp256k1_test::Error) -> Error {
    let result = match error_enum {
        secp256k1_test::Error::IncapableContext=> "IncapableContext",
        secp256k1_test::Error::InvalidPublicKey=> "InvalidPublicKey",
        secp256k1_test::Error::InvalidSecretKey=> "InvalidSecretKey",
        secp256k1_test::Error::InvalidRecoveryId=> "InvalidRecoveryId",
        secp256k1_test::Error::InvalidMessage=> "InvalidMessage",
        secp256k1_test::Error::IncorrectSignature=> "IncorrectSignature",
        secp256k1_test::Error::InvalidSignature=> "InvalidSignature",
    };
    Error(result.to_string())
}

fn to_message(message: &str) -> secp256k1::Message {
    let mut hasher = Sha256::default();
    let byte_message = message.as_bytes();
    hasher.input(byte_message);
    let output = hasher.result();
    const DIGEST_LENGTH: usize = 32;
    let mut converted_digest = [0u8; DIGEST_LENGTH];
    for i in 0..DIGEST_LENGTH {
        converted_digest[i] = output[i];
    }
    secp256k1::Message::parse(&converted_digest)
}

pub fn initialize() -> CommonParameters {
    let secp256k1 = secp256k1_test::Secp256k1::new();
    CommonParameters{secp256k1, rng: rand::thread_rng()}
}

pub fn generate_key_pair(common_parameters: &mut CommonParameters) -> Result<(
    PublicKey, PrivateKey), Error> {
    let key_pair_result = common_parameters.
        secp256k1.generate_keypair(&mut common_parameters.rng);
    if key_pair_result.is_err() {
        return Err(from_secp256k1_test_error(key_pair_result.err().unwrap()));
    }
    let (private_key_input, _) = key_pair_result.unwrap();
    let private_key_result = secp256k1::SecretKey::parse(
        array_ref!(private_key_input, 0, 32));
    if private_key_result.is_err() {
        return Err(from_secp256k1_error(private_key_result.err().unwrap()));
    }
    let private_key = private_key_result.unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&private_key);
    Ok((PublicKey{public_key}, PrivateKey{private_key}))
}

pub fn sign(message: &str, private_key: &PrivateKey) -> Result<(Signature, RecoveryId), Error> {
    let message_input = to_message(&message);
    let result = secp256k1::sign(
        &message_input, &private_key.private_key);
    match result {
        Ok((signature, recovery_id)) => Ok(
            (Signature{signature}, RecoveryId{recovery_id})),
        Err(error_enum) => Err(from_secp256k1_error(error_enum)),
    }
}

pub fn verify(message: &str, signature: &Signature, public_key: &PublicKey) -> bool {
    let message_input = to_message(&message);
    secp256k1::verify(&message_input, &signature.signature, &public_key.public_key)
}

pub fn recover(message: &str, signature: &Signature,
               recovery_id: &RecoveryId) -> Result<PublicKey, Error> {
    let message_input = to_message(&message);
    let result = secp256k1::recover(
        &message_input, &signature.signature, &recovery_id.recovery_id);
    match result {
        Ok(public_key) => Ok(PublicKey{public_key}),
        Err(error_enum) => Err(from_secp256k1_error(error_enum)),
    }
}

#[test]
fn test_sign_and_verify_short_message() {
    let mut common_parameters = initialize();
    let message = "hello world";
    let (public_key, private_key) = generate_key_pair(&mut common_parameters).unwrap();
    let (signature, _) = sign(&message, &private_key).unwrap();
    assert!(verify(&message, &signature, &public_key));
}

#[test]
fn test_sign_and_verify_long_message() {
    let mut common_parameters = initialize();
    let message = "hello from the other side hello darkness my old friend";
    let (public_key, private_key) = generate_key_pair(&mut common_parameters).unwrap();
    let (signature, _) = sign(&message, &private_key).unwrap();
    assert!(verify(&message, &signature, &public_key));
}

#[test]
fn test_recover_public_key() {
    let mut common_parameters = initialize();
    let message = "hello world";
    let (public_key, private_key) = generate_key_pair(&mut common_parameters).unwrap();
    let (signature, recovery_id) = sign(&message, &private_key).unwrap();
    assert_eq!(recover(&message, &signature, &recovery_id).unwrap(), public_key);
}
