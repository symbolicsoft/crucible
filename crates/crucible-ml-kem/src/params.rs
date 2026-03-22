/// ML-KEM global constants per FIPS 203.
pub const N: usize = 256;
pub const Q: u32 = 3329;
/// Primitive 256th root of unity mod q.
pub const ZETA: u32 = 17;

/// An ML-KEM parameter set.
#[derive(Debug, Clone)]
pub struct MlKemParams {
    pub name: &'static str,
    pub k: usize,
    pub eta1: usize,
    pub eta2: usize,
    pub du: usize,
    pub dv: usize,
}

pub const ML_KEM_512: MlKemParams = MlKemParams {
    name: "ML-KEM-512",
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};

pub const ML_KEM_768: MlKemParams = MlKemParams {
    name: "ML-KEM-768",
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};

pub const ML_KEM_1024: MlKemParams = MlKemParams {
    name: "ML-KEM-1024",
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

pub const ALL_PARAMS: &[MlKemParams] = &[ML_KEM_512, ML_KEM_768, ML_KEM_1024];

pub fn params_by_name(name: &str) -> Option<&'static MlKemParams> {
    ALL_PARAMS.iter().find(|p| p.name == name)
}
