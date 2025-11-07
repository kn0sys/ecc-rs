struct SchnorrProof {
   g: ecc::Point,
   p: ecc::Point,
   c: ecc::Scalar,
   q: ecc::Point,
   s: ecc::Scalar
}

impl SchnorrProof {
    /**
    * Use SchnorrProof::init(scalar, point) to create a new proof
    */
    fn init(x: ecc::Scalar, p: ecc::Point) -> SchnorrProof {
        let g = ecc::G.clone();
        // we won't store the secret x here
        // let r be a random scalar not stored in self
        let r = ecc::Scalar::random().unwrap();
        // let q = rg.
        let q = (ecc::G.clone() * r.clone()).unwrap();
        // now Prover would send P and Q to Verifier.
        // once Verifier receives P and Q, she gives
        // an interactive challenge c to Prover.
        let c = ecc::Scalar::random().unwrap();
        // once Prover received the challenge c, let s = r + c * x.
        let s = (r.clone() + (c.clone() * x).unwrap()).unwrap();
        // Prover would send s to Verifier. This completes the full proof.
        SchnorrProof { g, p, c, q, s }
   }

    /**
     * once Verifier receives the full proof, she can now verify it.
     */
     fn verify(&self) -> bool {
         // return s * g == q + c * p
         (self.g.clone() * self.s.clone()).unwrap() == (self.q.clone() + (self.p.clone() * self.c.clone()).unwrap()).unwrap() 
     }
}

//test 1 (should work)
let prvkey = ecc::Scalar::random().unwrap();
let pubkey = ecc::G.clone() * prvkey.clone();
let proof1 = SchnorrProof::init(prvkey, pubkey.unwrap());
// also try NISchnorrProof
if proof1.verify() {
    println!("Proof1 Verified!");
} else {
    println!("Something's wrong (T_T)!");
}
// test 2 (should NOT work)
let prvkey2 = ecc::Scalar::random().unwrap();
let s =  ecc::Scalar::new(num::BigInt::from(1)).unwrap();
let s2 = prvkey2.clone() + s;
let pubkey2 = ecc::G.clone() * s2.unwrap();
let proof2 = SchnorrProof::init(prvkey2, pubkey2.unwrap());
// also try NISchnorrProof
if proof2.verify() {
    println!("Proof2 Verified!");
} else {
    println!("Something's wrong (T_T)!")
}
