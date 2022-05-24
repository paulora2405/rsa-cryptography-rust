// #![allow(dead_code)]
// #![allow(unused_imports)]
// #![allow(unused_mut)]
#![allow(unused_variables)]

pub mod encryption;
pub mod euclidean;
pub mod key_generator;
pub mod mod_exponentiation;
pub mod primality;
use crate::key_generator::KeyPair;

fn main() {
    let key_pair = KeyPair::generate_keys(32, true);
}
