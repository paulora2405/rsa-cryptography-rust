use num_bigint::{BigInt, BigUint, ToBigInt};

// pub fn gcd(a: &mut BigUint, b: &mut BigUint) -> BigUint {
//     if b > a {
//         swap(a, b);
//     }

//     let mut r: BigUint = a % b;
//     if r == 0u8.to_biguint().unwrap() {
//         return *b;
//     }

//     gcd(b, &mut r)
// }

// pub fn gcd_iter(a: &mut BigUint, b: &mut BigUint) -> BigUint {
//     while *b > 0u8.to_biguint().unwrap() {
//         *a %= *b;
//         swap(a, b)
//     }
//     *a
// }

pub fn euclides_extended(a: &mut BigUint, b: &mut BigUint) -> (BigUint, BigUint, BigUint) {
    let (mut old_r, mut rem) = (BigInt::from(a.clone()), BigInt::from(b.clone()));
    let (mut old_s, mut coeff_s) = (1u8.to_bigint().unwrap(), 0u8.to_bigint().unwrap());
    let (mut old_t, mut coeff_t) = (0u8.to_bigint().unwrap(), 1u8.to_bigint().unwrap());

    while rem != 0u8.to_bigint().unwrap() {
        let quotient = old_r.clone() / rem.clone();

        update_step(&mut rem, &mut old_r, &quotient);
        update_step(&mut coeff_s, &mut old_s, &quotient);
        update_step(&mut coeff_t, &mut old_t, &quotient);
    }

    if old_r < 0u8.to_bigint().unwrap() {
        old_r *= -1u8.to_bigint().unwrap();
    }
    if old_s < 0u8.to_bigint().unwrap() {
        old_s *= -1u8.to_bigint().unwrap();
    }
    if old_t < 0u8.to_bigint().unwrap() {
        old_t *= -1u8.to_bigint().unwrap();
    }

    (
        old_r.to_biguint().unwrap(),
        old_s.to_biguint().unwrap(),
        old_t.to_biguint().unwrap(),
    )
}

fn update_step(a: &mut BigInt, old_a: &mut BigInt, quotient: &BigInt) {
    // println!("{}", &a);
    // println!("{}", &old_a);
    // println!("{}", &quotient);
    let tmp = a.clone();
    *a = &*old_a - quotient * &tmp;
    *old_a = tmp;
}
