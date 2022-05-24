pub fn gcd(a: &mut u128, b: &mut u128) -> u128 {
    if b > a {
        *a ^= *b;
        *b ^= *a;
        *a ^= *b;
    }

    let mut r: u128 = *a % *b;
    if r == 0 {
        return *b;
    }

    gcd(b, &mut r)
}

pub fn gcd_iter(a: &mut u128, b: &mut u128) -> u128 {
    while *b > 0 {
        *a %= *b;
        std::mem::swap(a, b);
    }
    *a
}

pub fn euclides_extended(a: u128, b: u128) -> (u128, u128, u128) {
    let (mut old_r, mut rem) = (a, b);
    let (mut old_s, mut coeff_s) = (1, 0);
    let (mut old_t, mut coeff_t) = (0, 1);

    while rem != 0 {
        let quotient = old_r / rem;

        update_step(&mut rem, &mut old_r, quotient);
        update_step(&mut coeff_s, &mut old_s, quotient);
        update_step(&mut coeff_t, &mut old_t, quotient);
    }

    (old_r, old_s, old_t)
}

fn update_step(a: &mut u128, old_a: &mut u128, quotient: u128) {
    let tmp = *a;
    *a = old_a.wrapping_sub(quotient.wrapping_mul(tmp));
    *old_a = tmp;
}
