use num_bigint::BigUint;

#[must_use]
pub fn text_to_numeric(text: &String) -> BigUint {
    BigUint::from_bytes_le(text.as_bytes())
}

#[must_use]
pub fn numeric_to_text(num: &BigUint) -> String {
    String::from_utf8(num.to_bytes_le()).expect("Could not convert Numeric value to a String")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numeric_to_text() {
        let bytes: Vec<u8> = vec![84u8, 101u8, 115u8, 116u8];
        let num = BigUint::from_bytes_le(&bytes);
        println!("{}", num.bits());
        let text = numeric_to_text(&num);
        assert_eq!(text, "Test");
    }

    #[test]
    fn test_text_to_numeric() {
        let text = "Test";
        let num = text_to_numeric(&text.to_owned());
        println!("{}", num);
    }
}
