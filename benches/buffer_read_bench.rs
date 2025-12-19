use criterion::{criterion_group, criterion_main, Criterion};
use rrsa_lib::key::{Key, KeyPair};
use std::fs::File;
use std::io::{BufRead, Read};
use std::str::FromStr;

fn bufreader_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encoding from file");
    group.sample_size(20);
    // group.measurement_time(Duration::from_millis(500));
    // group.warm_up_time(Duration::from_millis(100));

    group.bench_function("Control", |b| {
        b.iter(|| {
            let pub_key = pair_4096().public_key;

            let mut input = File::open("messages/big.txt").unwrap();
            let mut output = File::create("messages/big.txt.encoded_control").unwrap();

            pub_key.encode(&mut input, &mut output).unwrap();
        })
    });
    group.bench_function("Buffer Reader", |b| {
        b.iter(|| {
            let pub_key = pair_4096().public_key;

            let input = File::open("messages/big.txt").unwrap();
            let mut output = File::create("messages/big.txt.encoded_buf_r").unwrap();

            let mut input = std::io::BufReader::with_capacity(1_048_576_usize, input);
            // let mut output = std::io::BufWriter::with_capacity(1_048_576_usize, output);

            pub_key.encode(&mut input, &mut output).unwrap();
        })
    });
    group.bench_function("Buffer Writter", |b| {
        b.iter(|| {
            let pub_key = pair_4096().public_key;

            let mut input = File::open("messages/big.txt").unwrap();
            let output = File::create("messages/big.txt.encoded_buf_w").unwrap();

            // let mut input = std::io::BufReader::with_capacity(1_048_576_usize, input);
            let mut output = std::io::BufWriter::with_capacity(1_048_576_usize, output);

            pub_key.encode(&mut input, &mut output).unwrap();
        })
    });
    group.bench_function("Buffer Reader/Writter", |b| {
        b.iter(|| {
            let pub_key = pair_4096().public_key;

            let input = File::open("messages/big.txt").unwrap();
            let output = File::create("messages/big.txt.encoded_buf_rw").unwrap();

            let mut input = std::io::BufReader::with_capacity(1_048_576_usize, input);
            let mut output = std::io::BufWriter::with_capacity(1_048_576_usize, output);

            pub_key.encode(&mut input, &mut output).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bufreader_bench);
criterion_main!(benches);

fn pair_4096() -> KeyPair {
    let pub_str = r"rrsa 8a171c456a76fa677632c86d79e76a08e9bd619d877b665195fb1d8e506c5fb93277da524842690e855d860644e6050da582f0fe632763a120e0d316cfbccc3e44cf6c8a2d3906690d8ab6133466f210e100213762f1a7b674307f491c6eba0f120a59fd9a8084ca43dfc43988837546fa0cf5e471703f6588d12a35607b20a8604bd989573ca3fea13637dfe31d77efc4f2919b6a8afc5dd58f78cb77a2e000210a636a8240a59c37eebda30adfe85025643f0592bafcb47e6d01d9a50132e23944044af48ded1e5c1517cbcb3bfb4f3ed488a778503ddf4d8de19ae2919ca3c6a78fd9338fe75d5800c45d4c7f9fe5a49967d285fe872063155ce41915e68728a2bc61fe33202d446c19a1a2a685e05cc006b9722c2c58287880f4ebe541f07feb5088290b1ddfce91aeddcd2d051bf33a02144ea6ecc6c1248d8de0702678d85edf7d6a82bc02d6d6523a87abc6c8dbf965a87e410dadff0a62fefded77f0dc4a0b1a65587c2c546d35e4b7ef85a159b2359d32e56df33cce92fb2a287fd1ee39cb940de89c30cd29b8eeb483ad5ff3d948bcbf17a4641876c55b1ba2026f4b08b96716c8b1038252d84610e491f14d5e4994025918aa5ea083e42d767eb8ee3e4e78c4f3a6afd69642f4f2704525a69141762f7448c9bd4e6d42c9b18358d6e405115579f7834869a9e68f8b0ce9ccbc7cf46119ce464b244d5b58458f8b
";
    let priv_str = r"-----BEGIN RSA-RUST PRIVATE KEY-----
8a171c456a76fa677632c86d79e76a08e9bd619d877b665195fb1d8e506c5fb93277da524842690e855d860644e6050da582f0fe632763a120e0d316cfbccc3e44cf6c8a2d3906690d8ab6133466f210e100213762f1a7b674307f491c6eba0f120a59fd9a8084ca43dfc43988837546fa0cf5e471703f6588d12a35607b20a8604bd989573ca3fea13637dfe31d77efc4f2919b6a8afc5dd58f78cb77a2e000210a636a8240a59c37eebda30adfe85025643f0592bafcb47e6d01d9a50132e23944044af48ded1e5c1517cbcb3bfb4f3ed488a778503ddf4d8de19ae2919ca3c6a78fd9338fe75d5800c45d4c7f9fe5a49967d285fe872063155ce41915e68728a2bc61fe33202d446c19a1a2a685e05cc006b9722c2c58287880f4ebe541f07feb5088290b1ddfce91aeddcd2d051bf33a02144ea6ecc6c1248d8de0702678d85edf7d6a82bc02d6d6523a87abc6c8dbf965a87e410dadff0a62fefded77f0dc4a0b1a65587c2c546d35e4b7ef85a159b2359d32e56df33cce92fb2a287fd1ee39cb940de89c30cd29b8eeb483ad5ff3d948bcbf17a4641876c55b1ba2026f4b08b96716c8b1038252d84610e491f14d5e4994025918aa5ea083e42d767eb8ee3e4e78c4f3a6afd69642f4f2704525a69141762f7448c9bd4e6d42c9b18358d6e405115579f7834869a9e68f8b0ce9ccbc7cf46119ce464b244d5b58458f8b
29e6a54f72e4b34a9d94ff3828db4d537309620b58c6dadf3ab13de0a70a9b6928a5317bf22d248fa16c2574d5872e555bb985c2caf772c5bba23cab1951e26faa957e0bd7790c36e84304c8830811bf89666eadcdba21f7bcfdd241aefcf23c0c6f53ab1e2c8d1e8ac5e556c7d38bcc83a7571d80465d164413a3c91a8381ff5568ee933c034c87c10720a130db0a3f98f539b57cf8bb67059c493d040a4a09fffc94fa0697f32899d83976b5a0076ffa4896ceec1d0cfcffb7b7ee00a1827d1e7f4306337ab54e97065778212d0c2e999407fb3908b01d87fcdb4e121db8f801196b0eaf14a551af985bfd2b6f36678a307a4e6916388e5d42683356614cd7951c694730d55a7e139e6e1bd0ee36042c1358c704141abe95fd3ab8ab3a7a4c54183dbc1c6c70cafc815263fe1f8e020b4a169e0303376c30c2adc987b68c28996fcd9da0ba83fe52ee2d2fea92145e9ac66c79f753133ba2d52738aaa08e40b7566eb618c10f19b3df04e6cc5f2d3ba9fc7efc7884565a6ef161a737769d5125a76ba2044119a6950e9ccfbfcd4c294a2aa2665d8819a31b50210e4033cd194e0b9d828e684aeada7e68c2f2e8edd1cd5dbbd08ea94da100f1a8c407a8c12b35f0ec004ee592d51946f74ead50e7ba73bab3f75bd197a757c76373f8e1a5c0d7b09e30572751e1084a165f7ccdf82d45c9de1401b4870821012e79e6744431
-----END RSA-RUST PRIVATE KEY-----
";
    let public_key = Key::from_str(pub_str).unwrap();
    let private_key = Key::from_str(priv_str).unwrap();

    KeyPair {
        public_key,
        private_key,
    }
}

const FILENAME: &str = "messages/big.txt";

pub fn read_unbuffered_one_character_at_a_time() -> std::io::Result<u64> {
    let mut file = File::open(FILENAME)?;
    let len = file.metadata().expect("Failed to get file metadata").len() as usize;
    let mut v: Vec<u8> = vec![0u8; len];
    for index in 0..len {
        file.read_exact(&mut v[index..(index + 1)])?;
    }
    let s = String::from_utf8(v).expect("file is not UTF-8?");
    let mut total = 0u64;
    for line in s.lines() {
        total += get_count_from_line(line);
    }
    Ok(total)
}

pub fn read_buffered_allocate_string_every_time() -> std::io::Result<u64> {
    let file = File::open(FILENAME)?;
    let reader = std::io::BufReader::new(file);
    let mut total = 0u64;
    for line in reader.lines() {
        let s = line?;
        total += get_count_from_line(&s);
    }
    Ok(total)
}

pub fn read_buffered_reuse_string() -> std::io::Result<u64> {
    let file = File::open(FILENAME)?;
    let mut reader = std::io::BufReader::new(file);
    let mut string = String::new();
    let mut total = 0u64;
    while reader.read_line(&mut string).unwrap() > 0 {
        total += get_count_from_line(&string);
        string.clear();
    }
    Ok(total)
}

pub fn read_buffer_whole_string_into_memory() -> std::io::Result<u64> {
    let mut file = File::open(FILENAME)?;
    let mut s = String::new();
    file.read_to_string(&mut s)?;
    let mut total = 0u64;
    for line in s.lines() {
        total += get_count_from_line(line);
    }
    Ok(total)
}

fn get_count_from_line(s: &str) -> u64 {
    if s.is_empty() {
        return 0;
    }
    let mut parts = s.split_ascii_whitespace();
    let _ = parts.next();
    parts.next().unwrap().parse::<u64>().unwrap()
}
