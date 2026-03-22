use crucible_core::orchestrator::Battery;
use crate::params;

mod category1_norms;
mod category2_arith;
mod category3_signing;
mod category4_verify;
mod category5_serial;
mod category6_timing;

pub fn ml_dsa_battery() -> Battery {
    Battery {
        name: "ml-dsa".to_string(),
        categories: vec![
            category1_norms::category(),
            category2_arith::category(),
            category3_signing::category(),
            category4_verify::category(),
            category5_serial::category(),
            category6_timing::category(),
        ],
        parameter_sets: params::ALL_PARAMS
            .iter()
            .map(|p| p.name.to_string())
            .collect(),
    }
}
