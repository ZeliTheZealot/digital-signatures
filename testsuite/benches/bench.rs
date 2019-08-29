#![feature(test)]
extern crate test;
extern crate rand;
extern crate arrayref;
extern crate common;
extern crate multisig;

use test::Bencher;
//use common::ecdsa;
//use multisig::schnorr;

//this bench takes the longest time, compared to key generation and verification
//i know this from benching libsecp256k1
#[cfg(test)]
#[bench]
fn bench_sign_message_libsecp256k1(b: &mut Bencher) {
    let mut common_parameters = common::ecdsa::initialize();
    let message = "hello world";
    let (_, private_key) = common::ecdsa::generate_key_pair(&mut common_parameters).unwrap();
    b.iter(|| {
        let _ = common::ecdsa::sign(&message, &private_key);
    });
}

//consider writing other benches
#[cfg(test)]
#[bench]
fn bench_sign_message_schnorr(b: &mut Bencher) {
    let common_parameters = multisig::schnorr::initialize("this thing");
    let message = "hello world";
    let key_pair = multisig::schnorr::generate_key_pair().unwrap();
    b.iter(|| {
        let _ = multisig::schnorr::sign(message, &key_pair, &common_parameters).unwrap();
    })
}