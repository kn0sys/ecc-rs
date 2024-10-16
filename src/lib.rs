//! An intuitive ECC library wrapped around Dalek Cryptography for tutorial purposes.
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_COMPRESSED,
    edwards::{
        EdwardsPoint,
    },
    scalar::Scalar as DalekScalar,
};
use num::{
    bigint::Sign,
    BigInt,
    pow,
};
use sha2::{
    Digest,
    Sha512,
};
use rand::RngCore;

/// L value as defined at https://eprint.iacr.org/2008/013.pdf
const L: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

fn l_as_big_int() -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, &hex::decode(L).unwrap_or_default())
}

#[derive(Debug)]
pub struct Scalar {
    dalek: DalekScalar,
    hex: String,
}

#[derive(Debug)]
pub struct Point {
    dalek: EdwardsPoint,
    hex: String
}

#[derive(Debug)]
pub enum EccError {
    Scalar,
    Point
}

fn big_int_to_array(mut n: BigInt) -> [u8; 32] {
    let mut array: [u8; 32] = [0_u8; 32];
    for (index, _) in array.into_iter().enumerate() {
        let b = n.clone() & BigInt::from(0xff);
        array[index] = u8::from_le_bytes([b.to_bytes_le().1[0]]);
        n = (n - b) / BigInt::from(256);
    }
    array
} 

fn to_hex (mut n: BigInt) -> String {
    let mut a = [0u8; 32];
    for (index, _) in a.into_iter().enumerate() {
        let b: BigInt = &n & BigInt::from(255_u8);
        let s: &str = &format!("{b}");
        let parse = match s.parse::<u8>() {
            Ok(v) => v,
            _=> 0,
        };
        a[index] = parse;
        n = (&n - b) / BigInt::from(256_u16);
    }
    hex::encode(a)
}

impl Scalar {
    pub fn new(n: BigInt) -> Result<Self, EccError> {
        let l = l_as_big_int();
        if n < BigInt::ZERO || n >= l {
            return Err(EccError::Scalar);
        }
        let array = big_int_to_array(n.clone());
        let dalek: DalekScalar = DalekScalar::from_bytes_mod_order(array);
        let hex: String = to_hex(n.clone());
        Ok(Scalar { dalek, hex })
    }
    pub fn divide(&self, n: Scalar) -> Result<Scalar, EccError> {
        let quo = self.get_dalek() * n.get_dalek().invert();
        let prod = n.get_dalek() * quo;
        let bi = BigInt::from_bytes_le(Sign::Plus, prod.as_bytes());
        Scalar::new(bi)
    } 
    pub fn pow(&self, n: usize) -> Result<Scalar, EccError> {
        let bi = BigInt::from_bytes_le(Sign::Plus, self.get_dalek().as_bytes());
        let result = pow(bi, n);
        Scalar::new(result)
    }
    pub fn random() -> Result<Scalar, EccError> {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        let dalek = DalekScalar::from_bytes_mod_order(data);
        let bi = BigInt::from_bytes_le(Sign::Plus, dalek.as_bytes());
        Scalar::new(bi)
    }
    pub fn get_dalek(&self) -> DalekScalar {
        self.dalek
    }
    pub fn get_hex(&self) -> String {
        String::from(&self.hex)
    }
}

impl std::ops::Add<Scalar> for Scalar {
    type Output = Result<Scalar, EccError>;
    fn add (self, _rhs: Scalar) -> Result<Scalar, EccError> {
        let sum = self.get_dalek() + _rhs.get_dalek();
        let bi = BigInt::from_bytes_le(Sign::Plus, sum.as_bytes());
        Scalar::new(bi)
    }
}

impl std::ops::Sub<Scalar> for Scalar {
    type Output = Result<Scalar, EccError>;
    fn sub(self, _rhs: Scalar) -> Result<Scalar, EccError> {
        let diff = self.get_dalek() - _rhs.get_dalek();
        let bi = BigInt::from_bytes_le(Sign::Plus, diff.as_bytes());
        Scalar::new(bi)
    }
}

impl std::ops::Mul<Scalar> for Scalar {
    type Output = Result<Scalar, EccError>;
    fn mul(self, _rhs: Scalar) -> Result<Scalar, EccError> {
        let prod = self.get_dalek() * _rhs.get_dalek();
        let bi = BigInt::from_bytes_le(Sign::Plus, prod.as_bytes());
        Scalar::new(bi)
    }
}

impl std::ops::Neg for Scalar {
    type Output = Result<Scalar, EccError>;
    fn neg(self) -> Result<Scalar, EccError> {
        let minus = -self.get_dalek();
        let bi = BigInt::from_bytes_le(Sign::Plus, minus.as_bytes());
        Scalar::new(bi)
    }
}

impl Point {
    pub fn base_generator() -> Result<Point, EccError> {
        let dalek = ED25519_BASEPOINT_COMPRESSED.decompress().unwrap_or_default();
        let hex = to_hex(BigInt::from_bytes_le(Sign::Plus, dalek.compress().as_bytes()));
        Ok(Point { dalek, hex })
    }
    pub fn zero() -> Result<Point, EccError> {
        let z = Point::base_generator()? - Point::base_generator()?;
        let point = z?;
        let dalek = point.get_dalek();
        let hex = point.get_hex();
        Ok(Point { dalek, hex })
    }
    pub fn get_dalek(&self) -> EdwardsPoint {
        self.dalek
    }
    pub fn get_hex(&self) -> String {
        String::from(&self.hex)
    }
}

impl std::ops::Add<Point> for Point {
    type Output = Result<Point, EccError>;
    fn add(self, _rhs: Point) -> Result<Point, EccError> {
        let dalek = self.get_dalek() + _rhs.get_dalek();
        let bi = BigInt::from_bytes_le(Sign::Plus, dalek.compress().as_bytes());
        let hex = to_hex(bi);
        Ok( Point { dalek, hex } )
    }
}

impl std::ops::Sub<Point> for Point {
    type Output = Result<Point, EccError>;
    fn sub(self, _rhs: Point) -> Result<Point, EccError> {
        let dalek = self.get_dalek() - _rhs.get_dalek();
        let bi = BigInt::from_bytes_le(Sign::Plus, dalek.compress().as_bytes());
        let hex = to_hex(bi);
        Ok( Point { dalek, hex } )
    }
}

impl std::ops::Mul<Scalar> for Point {
    type Output = Result<Point, EccError>;
    fn mul(self, _rhs: Scalar) -> Result<Point, EccError> {
        let dalek = self.get_dalek() * _rhs.get_dalek();
        let bi = BigInt::from_bytes_le(Sign::Plus, dalek.compress().as_bytes());
        let hex = to_hex(bi);
        Ok( Point {dalek, hex })
    }
}

pub fn hash_to_scalar(s: Vec<&str>) -> Result<Scalar, EccError> {
    let mut result = String::new();
    for v in &s {
        let mut hasher = Sha512::new();
        hasher.update(v);
        let hash = hasher.finalize().to_owned();
        result += &hex::encode(&hash[..]);
    }
    loop {
        let mut hasher = Sha512::new();
        hasher.update(&result);
        let hash = hasher.finalize().to_owned();
        let mut hash_container: [u8; 32] = [0u8; 32];
        for (index, byte) in result.as_bytes().iter().enumerate() {
            if index == hash_container.len() - 1 {
                break;
            }
            hash_container[index] = *byte;
        }
        let hash_value = BigInt::from_bytes_le(Sign::Plus, &hash_container);
        if hash_value < l_as_big_int() {
            return Scalar::new(hash_value)
        }
        result = hex::encode(&hash[..]);
    }
}

// Tests
//-------------------------------------------------------------------------------
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn new_scalar_test() -> Result<(), EccError> {
        let scalar = Scalar::new(BigInt::from(1));
        let expected = to_hex(BigInt::from(1));
        assert_eq!(expected, scalar?.get_hex());
        Ok(())
    }
    
    #[test]
    fn add_scalar_test() -> Result<(), EccError> {
        let scalar_one = Scalar::new(BigInt::from(1));
        let scalar_two = Scalar::new(BigInt::from(2));
        let sum = scalar_one? + scalar_two?;
        let expected = Scalar::new(BigInt::from(3));
        assert_eq!(sum?.get_dalek(), expected?.get_dalek());
        Ok(())
    }

    #[test]
    fn sub_scalar_test() -> Result<(), EccError> {
        let scalar_one = Scalar::new(BigInt::from(1));
        let scalar_two = Scalar::new(BigInt::from(2));
        let diff = scalar_one? - scalar_two?;
        let expected_bi = l_as_big_int();
        let expected = Scalar::new(expected_bi - BigInt::from(1));
        assert_eq!(expected?.get_dalek(), diff?.get_dalek());
        Ok(())
    }

    #[test]
    fn mul_scalar_test() -> Result<(), EccError> {
        let scalar_two = Scalar::new(BigInt::from(2));
        let scalar_three = Scalar::new(BigInt::from(3));
        let prod = scalar_two? * scalar_three?;
        let expected = Scalar::new(BigInt::from(6));
        assert_eq!(expected?.get_dalek(), prod?.get_dalek());
        Ok(())
    }

    #[test]
    fn div_scalar_test() -> Result<(), EccError> {
        let scalar_one = Scalar::new(BigInt::from(1));
        let scalar_two = Scalar::new(BigInt::from(2));
        let expected = Scalar::new(BigInt::from(1));
        let result = scalar_one?.divide(scalar_two?);
        assert_eq!(expected?.get_dalek(), result?.get_dalek());
        Ok(())
    }

    #[test]
    fn pow_scalar_test() -> Result<(), EccError> {
        let scalar_two = Scalar::new(BigInt::from(2));
        let result = scalar_two?.pow(3);
        let expected = Scalar::new(BigInt::from(8));
        assert_eq!(expected?.get_dalek(), result?.get_dalek());
        Ok(())
    }

    #[test]
    fn neg_scalar_test() -> Result<(), EccError> {
        let scalar_one = Scalar::new(BigInt::from(1));
        let expected = to_hex(l_as_big_int() - BigInt::from(1));
        let result = -scalar_one?;
        assert_eq!(expected, result?.get_hex());
        Ok(())
    }

    #[test]
    fn rnd_scalar_test() -> Result<(), EccError> {
        let rnd_scalar = Scalar::random();
        assert!(!rnd_scalar.is_err());
        Ok(())
    }

    #[test]
    fn base_generator_test() -> Result<(), EccError> {
        let g = Point::base_generator();
        let expected = "5866666666666666666666666666666666666666666666666666666666666666".to_string();
        assert_eq!(expected, g?.get_hex());
        Ok(())
    }

    #[test]
    fn add_point_test() -> Result<(), EccError> {
        let g = Point::base_generator();
        let g_again = Point::base_generator();
        let expected = "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022".to_string();
        let result = g? + g_again?;
        assert_eq!(expected, result?.get_hex());
        Ok(())
    }

    #[test]
    fn zero_point_test() -> Result<(), EccError> {
        let zero = Point::zero();
        let expected = "0100000000000000000000000000000000000000000000000000000000000000".to_string();
        assert_eq!(zero?.get_hex(), expected);
        Ok(())
    }

    #[test]
    fn mul_point_test() -> Result<(), EccError> {
        let g = Point::base_generator();
        let scalar_two = Scalar::new(BigInt::from(2));
        let prod = g? * scalar_two?;
        let expected = "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022".to_string();
        assert_eq!(expected, prod?.get_hex());
        Ok(())
    }
}

