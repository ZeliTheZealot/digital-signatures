extern crate rand;
extern crate rand_core;
extern crate rand_chacha;

use rand::{Rng, os::OsRng, SeedableRng}; //i'm using OsRng
use rand_core::{CryptoRng, RngCore};
use rand_chacha::ChaChaRng; //behaves badly
//use schnorrkel::{Keypair,Signature,signing_context}; //write full name


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

#[derive(Debug)]
pub struct Error(String);

pub fn initialize() -> CommonParameters {
    let schnorrkel = schnorrkel::signing_context(b"this signature does this thing");
    let mut csprng = ChaChaRng::from_seed([0u8; 32]);
    CommonParameters{schnorrkel, rng: csprng}
}

pub fn generate_key_pair(common_parameters: &mut CommonParameters) -> (PublicKey, PrivateKey) {
    let mut csprng = rand::os::OsRng::new().unwrap();
    let private_key = schnorrkel::SecretKey::generate_with(&mut csprng);
    let public_key = schnorrkel::SecretKey::to_public(&private_key);
    (PublicKey{public_key}, PrivateKey{private_key})
}

//pub fn generate_key_pair(common_parameters: &mut CommonParameters) -> () {
//    let mut csprng = ChaChaRng::from_seed([0u8; 32]);
//    let private_key = schnorrkel::Keypair::generate_with(&mut csprng);
    //let public_key = schnorrkel::SecretKey::to_public(&private_key);
    //(PublicKey{public_key}, PrivateKey{private_key})
//}

//pub fn sign(message: &str, private_key: &PrivateKey) -> Signature {
//    let
//}








































