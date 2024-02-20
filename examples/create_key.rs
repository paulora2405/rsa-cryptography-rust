use rrsa_lib::key::KeyPair;

fn main() {
    let key_pair = KeyPair::generate(Some(512), true, true, true);
    let pub_key = key_pair.public_key;
    let priv_key = key_pair.private_key;
    println!();
    println!("Public Key:\nr\"{pub_key}\"");
    println!();
    println!("Private Key:\nr\"{priv_key}\"");
}
