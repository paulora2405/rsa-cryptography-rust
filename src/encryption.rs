use num_bigint::BigUint;
use num_traits::Zero;

pub fn log_b(num: &BigUint) -> u16 {
    let mut num_ = num.clone();
    let mut bits: u16 = 0;
    while !num_.is_zero() {
        num_ >>= 1u8;
        bits += 1;
    }
    bits
}

pub fn text_to_numeric(text: &String) -> BigUint {
    let mut num = BigUint::from(0u8);
    let mut e = 0u32;
    for c in text.chars() {
        // mult by 32 because a char uses 4 bytes in rust
        num += u32::from(c) * BigUint::from(1u8) << (e * 8);
        e += 1;
    }
    num
}

// pub fn numeric_to_text(num: &BigUint) -> String {
//     let mut num_ = num.clone();
//     let mut text = String::from("");
//     while !num.is_zero() {
//         // let x: u8 = *&num_ & 255u8;
//         // let ch: char = char::from(x);
//         // text.push(ch);
//     }
//     text
// }
