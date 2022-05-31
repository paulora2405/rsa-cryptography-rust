# RSA Cryptography Implementation with Rust-lang

## About RSA
RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem that is widely used for secure data transmission.

In a public-key cryptosystem, the encryption key is public and distinct from the decryption key, which is kept secret (private). An RSA user creates and publishes a public key based on two large prime numbers, along with an auxiliary value. The prime numbers are kept secret. Messages can be encrypted by anyone, via the public key, but can only be decoded by someone who knows the prime numbers.

The security of RSA relies on the practical difficulty of factoring the product of two large prime numbers, the "factoring problem". Breaking RSA encryption is known as the RSA problem. Whether it is as difficult as the factoring problem is an open question. There are no published methods to defeat the system if a large enough key is used. 

## Compile and Run
To just build the binary:
```sh
$ cargo build --release
```

The binary will be in `target/release/rsa-implementation-rust`.

You can copy it to another directory with:
```sh
$ cp target/release/rsa-implementation-rust ./rsa-rust
```
And then run it from there by doing:
```sh
$ ./rsa-rust
```
The cli interface will guide you on how to use the avaiable subcommands.

If you wish to compile the binary and run it in another system, please be aware of GLIBC version incompatibility.

You are better of compiling it through the official Rust Docker image by doing:
```sh
$ sudo docker pull rust
$ sudo docker run --rm --user "$(id -u)":"$(id -g)" -v "$PWD":/usr/src/myapp -w /usr/src/myapp rust cargo build --release
```

## The math of RSA encryption

### Public and Private key generation
1. Select two big prime numbers `P` and `Q`
1. Calculate `N = P * Q`
1. Calculate `λ(N) = (P-1) * (Q-1)`
1. Find a `E` such that `gcd(e, λ(N)) = 1` and `1 < E < λ(N)`
1. Calculate `D` such that `E*D = 1 (mod λ(N))`

- The Public key will be `(N, E)`
- The Private key will be `(N, D)`

### Encryption and Decryption
Given a message `M` and a ciphered message `C`

#### Encryption
- Given the message `M` use <code>M<sup>E</sup> = C (mod N)</code> to calculate the ciphered message `C`

#### Decryption
- Given the ciphered message `C` use <code>C<sup>D</sup> = M (mod N)</code> to calculate the original message `M`
