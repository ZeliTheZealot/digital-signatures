#![feature(test)]

extern crate test;
use add_one::fibonacci;

#[cfg(test)]
mod tests {
    use add_one::fibonacci::fibonacci;
    use test::{black_box, Bencher};

    #[bench]
    fn libtest_benchmark(b: &mut Bencher) {
        // Inner closure, the actual test
        b.iter(|| {
            for i in 1..20 {
                fibonacci(black_box(i));
            }
        });
    }
}
