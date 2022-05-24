pub fn mod_pow(base: u128, exponent: u128, modulus: u128) -> u128 {
    // println!("{}", (modulus - 1));
    // println!("{}", (u128::MAX / (modulus - 1)));
    // assert!((modulus - 1) < (u128::MAX / (modulus - 1)));

    let mut result = 1;
    let mut base = base & modulus;
    let mut exponent = exponent;

    while exponent > 0 {
        let s_bit = exponent % 2 == 1;
        result = ((result * base) % modulus) * u128::from(s_bit) + result * (1 - u128::from(s_bit));

        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }
    result
}
