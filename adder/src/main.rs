use add_one::{self, print_one};
use add_two;
use art_mix_color;
use art_mix_color::PrimaryColor;
use rand;
use rand::Rng;

// way 1 by use mod
//mod sound;
//use sound::{instrument, violin};

//mod fruit;
//use fruit::apple;

// way 2 by use lib crate
use adder::fruit::apple;
use adder::sound::{instrument, violin};

fn main() {
    let number = rand::thread_rng().gen_range(1, 101);
    println!("call rand:{}", number);
    println!(
        "call art_mix_color:{:?}",
        art_mix_color::mix(PrimaryColor::Red, PrimaryColor::Blue)
    );
    println!("call add_one:{} ", add_one::add_one(29));
    println!("call add_two:{} ", add_two::add_two(29));

    instrument::clarinet();
    violin::print_violin();
    apple::print_apple();
    print_one::print_one("lfq");
}
