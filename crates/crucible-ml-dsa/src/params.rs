/// ML-DSA global constants per FIPS 204.
pub const N: usize = 256;
pub const Q: u32 = 8380417; // 2^23 - 2^13 + 1
pub const D: u32 = 13; // dropped bits from t
pub const ZETA: u32 = 1753; // 512th root of unity mod q

/// An ML-DSA parameter set.
#[derive(Debug, Clone)]
pub struct MlDsaParams {
    pub name: &'static str,
    pub k: usize,
    pub l: usize,
    pub eta: u32,
    pub tau: usize,
    pub lambda: usize, // collision strength of c_tilde, in bits
    pub gamma1: u32,
    pub gamma2: u32,
    pub beta: u32, // = tau * eta
    pub omega: usize,
}

pub const ML_DSA_44: MlDsaParams = MlDsaParams {
    name: "ML-DSA-44",
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    lambda: 128,
    gamma1: 1 << 17,   // 2^17
    gamma2: (Q - 1) / 88, // 95232
    beta: 78,           // 39 * 2
    omega: 80,
};

pub const ML_DSA_65: MlDsaParams = MlDsaParams {
    name: "ML-DSA-65",
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    lambda: 192,
    gamma1: 1 << 19,   // 2^19
    gamma2: (Q - 1) / 32, // 261888
    beta: 196,          // 49 * 4
    omega: 55,
};

pub const ML_DSA_87: MlDsaParams = MlDsaParams {
    name: "ML-DSA-87",
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    lambda: 256,
    gamma1: 1 << 19,   // 2^19
    gamma2: (Q - 1) / 32, // 261888
    beta: 120,          // 60 * 2
    omega: 75,
};

pub const ALL_PARAMS: &[MlDsaParams] = &[ML_DSA_44, ML_DSA_65, ML_DSA_87];

pub fn params_by_name(name: &str) -> Option<&'static MlDsaParams> {
    ALL_PARAMS.iter().find(|p| p.name == name)
}
