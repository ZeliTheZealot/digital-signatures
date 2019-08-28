#![feature(test)]
extern crate test;
extern crate rand;
extern crate arrayref;
extern crate common;

use test::Bencher;
use common::ecdsa;

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
