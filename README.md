# RSA Implementation with Rust-lang

## Compile and Run
To just build the binary:
```sh
$ cargo build --release
```
To build and run:
```sh
$ cargo run --release
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