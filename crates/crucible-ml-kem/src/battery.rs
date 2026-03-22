use crucible_core::orchestrator::Battery;
use crate::params;

mod category1_compress;
mod category2_ntt;
mod category3_bounds;
mod category4_decaps;
mod category5_serial;
mod category6_sampling;

/// Build the complete ML-KEM test battery.
pub fn ml_kem_battery() -> Battery {
    Battery {
        name: "ml-kem".to_string(),
        categories: vec![
            category1_compress::category(),
            category2_ntt::category(),
            category3_bounds::category(),
            category4_decaps::category(),
            category5_serial::category(),
            category6_sampling::category(),
        ],
        parameter_sets: params::ALL_PARAMS
            .iter()
            .map(|p| p.name.to_string())
            .collect(),
    }
}
