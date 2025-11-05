struct EncOut {
    rG: ecc::Point,
    yrp: ecc::Point
}

// Alice's encryption for (rg, Y + rp)
fn enc (y: ecc::Point, p: ecc::Point, bob_sk: ecc::Scalar) -> EncOut {
    let g = ecc::G.clone(); // base generator
    let bob_pk = g * bob_sk.clone();
    let expected = num::BigInt::from(69420);
    let p1 = num::BigInt::from(420);
    let p2 = expected - num::BigInt::from(420);
    let v = vec!["elgamal"];
    let h_scalar = ecc::hash_to_scalar(v).unwrap();
    let h_point = (ecc::G.clone() * h_scalar).unwrap();
    let r = ecc::Scalar::random().unwrap();
    let rG = (ecc::G.clone() * r.clone()).unwrap();
    let rp = p * r.clone();
    let yrp = (y + rp.unwrap()).unwrap();
    EncOut { rG, yrp }
}

// Bob's decryption for Y = C2 - x * C1
fn dec (e: EncOut, bob_sk: ecc::Scalar) -> Result<ecc::Point, ecc::EccError> {
    let g = ecc::G.clone(); // base generator
    let bob_pk = g * bob_sk.clone();
    let expected = num::BigInt::from(69420);
    let p1 = num::BigInt::from(420);
    let p2 = expected - num::BigInt::from(420);
    let v = vec!["elgamal"];
    let h_scalar = ecc::hash_to_scalar(v).unwrap();
    let h_point = (ecc::G.clone() * h_scalar).unwrap();
    let rgx = (e.rG * bob_sk.clone()).unwrap();
    e.yrp - rgx
}

// Simulation of scheme exection
fn elgamal (bob_sk: ecc::Scalar) {
    let g = ecc::G.clone(); // base generator
    let bob_pk = (g * bob_sk.clone()).unwrap();
    let expected = num::BigInt::from(69420);
    let p1 = num::BigInt::from(420);
    let p2 = expected.clone() - num::BigInt::from(420);
    let v = vec!["elgamal"];
    let h_scalar = ecc::hash_to_scalar(v).unwrap();
    let e1 = enc(((ecc::G.clone() * h_scalar.clone()).unwrap() * ecc::Scalar::new(p1).unwrap()).unwrap(), bob_pk.clone(), bob_sk.clone());
    let e2 = enc(((ecc::G.clone() * h_scalar.clone()).unwrap() * ecc::Scalar::new(p2).unwrap()).unwrap(), bob_pk.clone(), bob_sk.clone());
    let sum: EncOut = EncOut {
        rG: (e1.rG + e2.rG).unwrap(), // P1C1 + P2C2
        yrp: (e1.yrp + e2.yrp).unwrap() // P1C2 + P2C2
    };
    // Decrypt the sum
    let d = dec(sum, bob_sk.clone());
    let v = vec!["elgamal"];
    let h_scalar = ecc::hash_to_scalar(v).unwrap();
    let h_point = (ecc::G.clone() * h_scalar).unwrap();
    println!("expected 69420 * H = {}", (h_point.clone() * ecc::Scalar::new(expected).unwrap()).unwrap().get_hex());
    println!("actual = {}", (d.unwrap().get_hex()));
}
let bob_sk = ecc::Scalar::random().unwrap();
elgamal(bob_sk);
