//! An intuitive ECC library wrapped around Dalek Cryptography for tutorial purposes.
use curve25519_dalek::{
    constants,
    edwards::{
        EdwardsPoint,
    },
    scalar::Scalar as DalekScalar,
    traits::MultiscalarMul,
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

/// L value as defined at https://datatracker.ietf.org/doc/html/rfc8032#section-5.1
pub const L: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

fn l_as_big_int() -> BigInt {
    BigInt::from_bytes_le(Sign::Plus, &hex::decode(L).unwrap_or_default())
}

#[derive(Clone, Debug)]
pub struct Scalar {
    dalek: DalekScalar,
    hex: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    dalek: EdwardsPoint,
    hex: String
}

#[derive(Debug)]
pub enum EccError {
    Point,
    PointVector,
    Scalar,
    ScalarVector,
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
        let parse = s.parse::<u8>().unwrap_or_default();
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
        rand::rng().fill_bytes(&mut data);
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
        let dalek = constants::ED25519_BASEPOINT_COMPRESSED.decompress().unwrap_or_default();
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

impl std::ops::Neg for Point {
    type Output = Result<Point, EccError>;
    fn neg(self) -> Result<Point, EccError> {
        let dalek = -self.get_dalek();
        let bi = BigInt::from_bytes_le(Sign::Plus, dalek.compress().as_bytes());
        let hex = to_hex(bi);
        Ok( Point {dalek, hex } )
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

#[derive(Debug)]
pub struct ScalarVector(Vec<Scalar>);

impl ScalarVector {
    pub fn new(v: Vec<BigInt>) -> Result<Self, EccError> {
        let mut value: Vec<Scalar> = Vec::new();
        for i in v {
            value.push(Scalar::new(i)?);
        }
        Ok(ScalarVector(value))
    }
    pub fn sum_of_all(&self) -> Result<Scalar, EccError> {
        let mut value: Vec<BigInt> = Vec::new();
        for i in &self.0 {
            value.push(BigInt::from_bytes_le(Sign::Plus, i.get_dalek().as_bytes()));
        }
        Scalar::new(value.iter().sum())
    }
    /// sv ** sv (inner product)
    pub fn pow(&self, sv: ScalarVector) -> Result<Scalar, EccError> {
        let len = self.0.len();
        let mut z = Scalar::new(BigInt::from(0));
        if len != sv.0.len() { return Err(EccError::ScalarVector) }
        for i in 0..len {
            let s = self.0[i].clone() * sv.0[i].clone();
            z = z? + s?;
        }
        z
    }
}

impl std::ops::Add<ScalarVector> for ScalarVector {
    type Output = Result<ScalarVector, EccError>;
    fn add(self, _rhs: ScalarVector) -> Result<ScalarVector, EccError> {
        let mut value: Vec<Scalar> = Vec::new();
        let len = self.0.len();
        if len != _rhs.0.len() { return Err(EccError::ScalarVector) }
        for i in 0..len {
            let s = self.0[i].clone() + _rhs.0[i].clone();
            value.push(s?);
        }
        Ok(ScalarVector(value))
    }
}

impl std::ops::Sub<ScalarVector> for ScalarVector {
    type Output = Result<ScalarVector, EccError>;
    fn sub(self, _rhs: ScalarVector) -> Result<ScalarVector, EccError> {
        let mut value: Vec<Scalar> = Vec::new();
        let len = self.0.len();
        if len != _rhs.0.len() { return Err(EccError::ScalarVector) }
        for i in 0..len {
            let s = self.0[i].clone() - _rhs.0[i].clone();
            value.push(s?);
        }
        Ok(ScalarVector(value))
    }
}

impl std::ops::Mul<ScalarVector> for ScalarVector {
    type Output = Result<ScalarVector, EccError>;
    fn mul(self, _rhs: ScalarVector) -> Result<ScalarVector, EccError> {
        let mut value: Vec<Scalar> = Vec::new();
        let len = self.0.len();
        if len != _rhs.0.len() { return Err(EccError::ScalarVector) }
        for i in 0..len {
            let s = self.0[i].clone() * _rhs.0[i].clone();
            value.push(s?);
        }
        Ok(ScalarVector(value))
    }
}

impl std::ops::Mul<Scalar> for ScalarVector {
    type Output = Result<ScalarVector, EccError>;
    fn mul(self, _rhs: Scalar) -> Result<ScalarVector, EccError> {
        let mut value: Vec<Scalar> = Vec::new();
        for i in 0..self.0.len() {
            let s = self.0[i].clone() * _rhs.clone();
            value.push(s?);
        }
        Ok(ScalarVector(value))
    }
}

impl std::ops::Neg for ScalarVector {
    type Output = Result<ScalarVector, EccError>;
    fn neg(self) -> Result<ScalarVector, EccError> {
        let mut value: Vec<Scalar> = Vec::new();
        for i in 0..self.0.len() {
            let s = -self.0[i].clone();
            value.push(s?);
        }
        Ok(ScalarVector(value))
    }
}

#[derive(Debug)]
pub struct PointVector(Vec<Point>);

impl PointVector {
    pub fn new(v: Vec<Point>) -> Result<PointVector, EccError> {
        Ok(PointVector(v))
    }
    /// Multiscalar mulitplication - ScalarVector**PointVector
    pub fn multiexp(&self, sv: ScalarVector) -> Result<Point, EccError> {
       let points: Vec<EdwardsPoint> = self.0.iter().map(|p| p.get_dalek()).collect();
       let scalars: Vec<DalekScalar> = sv.0.iter().map(|s| s.get_dalek()).collect();
       let dalek = EdwardsPoint::multiscalar_mul(scalars, points);
       let hex = to_hex(BigInt::from_bytes_le(Sign::Plus, dalek.compress().as_bytes()));
       Ok(Point { dalek, hex })
    }
}

impl std::ops::Add<PointVector> for PointVector {
    type Output = Result<PointVector, EccError>;
    fn add(self, _rhs: PointVector) -> Result<PointVector, EccError> {
        let mut value: Vec<Point> = Vec::new();
        let len = self.0.len();
        if len != _rhs.0.len() { return Err(EccError::PointVector) }
        for i in 0..len {
            let s = self.0[i].clone() + _rhs.0[i].clone();
            value.push(s?);
        }
        Ok(PointVector(value))
    }
}

impl std::ops::Sub<PointVector> for PointVector {
    type Output = Result<PointVector, EccError>;
    fn sub(self, _rhs: PointVector) -> Result<PointVector, EccError> {
        let mut value: Vec<Point> = Vec::new();
        let len = self.0.len();
        if len != _rhs.0.len() { return Err(EccError::PointVector) }
        for i in 0..len {
            let s = self.0[i].clone() - _rhs.0[i].clone();
            value.push(s?);
        }
        Ok(PointVector(value))
    }
}

impl std::ops::Mul<ScalarVector> for PointVector {
    type Output = Result<PointVector, EccError>;
    fn mul(self, _rhs: ScalarVector) -> Result<PointVector, EccError> {
        let mut value: Vec<Point> = Vec::new();
        let len = self.0.len();
        if len != _rhs.0.len() { return Err(EccError::PointVector) }
        for i in 0..len {
            let s = self.0[i].clone() * _rhs.0[i].clone();
            value.push(s?);
        }
        Ok(PointVector(value))
    }
}

impl std::ops::Mul<Scalar> for PointVector {
    type Output = Result<PointVector, EccError>;
    fn mul(self, _rhs: Scalar) -> Result<PointVector, EccError> {
        let mut value: Vec<Point> = Vec::new();
        for i in 0..self.0.len() {
            let s = self.0[i].clone() * _rhs.clone();
            value.push(s?);
        }
        Ok(PointVector(value))
    }
}

impl std::ops::Neg for PointVector {
    type Output = Result<PointVector, EccError>;
    fn neg(self) -> Result<PointVector, EccError> {
        let mut value: Vec<Point> = Vec::new();
        for i in 0..self.0.len() {
            let s = -self.0[i].clone();
            value.push(s?);
        }
        Ok(PointVector(value))
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

    #[test]
    fn err_scalar_vector_test() {
        let mut v1: Vec<BigInt> = Vec::new();
        let mut v2: Vec<BigInt> = Vec::new();
        for i in 1..6 {
            if i < 4 {
                v1.push(BigInt::from(i));
            } else {
                v2.push(BigInt::from(i));
            }
        }
        let sv1 = ScalarVector::new(v1);
        let sv2 = ScalarVector::new(v2);
        let sv3 = sv1.unwrap() + sv2.unwrap();
        assert!(sv3.is_err());
    }

    #[test]
    fn add_scalar_vector_test() -> Result<(), EccError> {
        let mut v1: Vec<BigInt> = Vec::new();
        let mut v2: Vec<BigInt> = Vec::new();
        for i in 1..7 {
            if i < 4 {
                v1.push(BigInt::from(i));
            } else {
                v2.push(BigInt::from(i));
            }
        }
        let sv1 = ScalarVector::new(v1);
        let sv2 = ScalarVector::new(v2);
        let sv3 = sv1.unwrap() + sv2.unwrap();
        let five = Scalar::new(BigInt::from(5));
        assert_eq!(sv3?.0[0].get_dalek(), five?.get_dalek());
        Ok(())
    }

    #[test]
    fn sub_scalar_vector_test() -> Result<(), EccError> {
        let mut v1: Vec<BigInt> = Vec::new();
        let mut v2: Vec<BigInt> = Vec::new();
        for i in 1..7 {
            if i < 4 {
                v1.push(BigInt::from(i));
            } else {
                v2.push(BigInt::from(i));
            }
        }
        let sv1 = ScalarVector::new(v1);
        let sv2 = ScalarVector::new(v2);
        let sv3 = sv1.unwrap() - sv2.unwrap();
        let expected = "ead3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010".to_string();
        assert_eq!(expected, sv3?.0[0].get_hex());
        Ok(())
    }

    #[test]
    fn mul_scalar_vector_test() -> Result<(), EccError> {
        let mut v1: Vec<BigInt> = Vec::new();
        let mut v2: Vec<BigInt> = Vec::new();
        for i in 1..7 {
            if i < 4 {
                v1.push(BigInt::from(i));
            } else {
                v2.push(BigInt::from(i));
            }
        }
        let sv1 = ScalarVector::new(v1);
        let sv2 = ScalarVector::new(v2);
        let sv3 = sv1.unwrap() * sv2.unwrap();
        let expected = Scalar::new(BigInt::from(4));
        assert_eq!(expected?.get_hex(), sv3?.0[0].get_hex());
        Ok(())
    }

    #[test]
    fn sum_all_scalar_vector_test() -> Result<(), EccError> {
        let mut v1: Vec<BigInt> = Vec::new();
        for i in 1..7 {
            if i  < 4 {
                v1.push(BigInt::from(i));
            }
        }
        let sv1 = ScalarVector::new(v1);
        let expected = Scalar::new(BigInt::from(6));
        assert_eq!(expected?.get_hex(), sv1?.sum_of_all()?.get_hex());
        Ok(())
    }
    
    #[test]
    fn neg_scalar_vector_test() -> Result<(), EccError> {
        let mut v1: Vec<BigInt> = Vec::new();
        for i in 1..7 {
            if i  < 4 {
                v1.push(BigInt::from(i));
            }
        }
        let sv1 = ScalarVector::new(v1);
        let expected = "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010".to_string();
        let r_sv = -sv1?;
        assert_eq!(expected, r_sv?.0[0].get_hex());
        Ok(())
    }

    #[test]
    fn pow_scalar_vector_test() -> Result<(), EccError> {
        let mut v1: Vec<BigInt> = Vec::new();
        let mut v2: Vec<BigInt> = Vec::new();
        for i in 1..7 {
            if i < 4 {
                v1.push(BigInt::from(i));
            } else {
                v2.push(BigInt::from(i));
            }
        }
        let sv1 = ScalarVector::new(v1);
        let sv2 = ScalarVector::new(v2);
        let sv3 = sv1?.pow(sv2?);
        let expected = "2000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert_eq!(expected, sv3?.get_hex());
        Ok(())
    }

    #[test]
    fn add_point_vector_test() -> Result<(), EccError> {
        let mut v1: Vec<Point> = Vec::new();
        let mut v2: Vec<Point> = Vec::new();
        for i in 1..7 {
            if i < 4 {
                v1.push((Point::base_generator()? * Scalar::new(BigInt::from(i))?)?);
            } else {
                v2.push((Point::base_generator()? * Scalar::new(BigInt::from(i))?)?);
            }
        }
        let sv1 = PointVector::new(v1);
        let sv2 = PointVector::new(v2);
        let sv3 = sv1.unwrap() + sv2.unwrap();
        let expected = "edc876d6831fd2105d0b4389ca2e283166469289146e2ce06faefe98b22548df".to_string();
        assert_eq!(expected, sv3?.0[0].get_hex());
        Ok(())
    }
    
     #[test]
    fn sub_point_vector_test() -> Result<(), EccError> {
        let mut v1: Vec<Point> = Vec::new();
        let mut v2: Vec<Point> = Vec::new();
        for i in 1..7 {
            if i < 4 {
                v1.push((Point::base_generator()? * Scalar::new(BigInt::from(i))?)?);
            } else {
                v2.push((Point::base_generator()? * Scalar::new(BigInt::from(i))?)?);
            }
        }
        let sv1 = PointVector::new(v1);
        let sv2 = PointVector::new(v2);
        let sv3 = sv1.unwrap() - sv2.unwrap();
        let expected = "d4b4f5784868c3020403246717ec169ff79e26608ea126a1ab69ee77d1b16792".to_string();
        assert_eq!(expected, sv3?.0[0].get_hex());
        Ok(())
    }

    #[test]
    fn multiexp_point_vector_test() -> Result<(), EccError> {
        let mut v2: Vec<Point> = Vec::new();
        let mut b1: Vec<BigInt> = Vec::new();
        let mut b1_copy: Vec<BigInt> = Vec::new();
        let mut b2: Vec<BigInt> = Vec::new();
        for i in 1..7 {
            if i < 4 {
                b1.push(BigInt::from(i));
                b1_copy.push(BigInt::from(i));
            } else {
                v2.push((Point::base_generator()? * Scalar::new(BigInt::from(i))?)?);
                b2.push(BigInt::from(i));
            }
        }
        let pv2 = PointVector::new(v2);
        let sv1 = ScalarVector::new(b1);
        let sv1_copy = ScalarVector::new(b1_copy);
        let sv2 = ScalarVector::new(b2);
        let p = sv1?.pow(sv2?);
        let expected = Point::base_generator()? * p?;
        let actual = pv2?.multiexp(sv1_copy?);
        assert_eq!(expected?.get_hex(), actual?.get_hex());
        Ok(())
    }

}

