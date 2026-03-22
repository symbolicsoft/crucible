use crucible_core::harness::Harness;
use crucible_core::orchestrator::{self, Battery, RunConfig};
use crucible_ml_dsa::battery::ml_dsa_battery;
use crucible_ml_kem::battery::ml_kem_battery;
use std::env;
use std::process;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_usage();
        process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let harness_cmd = &args[1];
    let harness_args: Vec<&str> = args[2..].iter()
        .take_while(|a| !a.starts_with("--"))
        .map(|s| s.as_str())
        .collect();

    // Parse flags from remaining args.
    let flag_args: Vec<&String> = args[2..].iter()
        .skip_while(|a| !a.starts_with("--"))
        .collect();

    let mut config = RunConfig::default();
    let mut output_json = false;
    let mut timeout_secs = 30u64;
    let mut battery_name = String::from("ml-kem");

    let mut i = 0;
    while i < flag_args.len() {
        match flag_args[i].as_str() {
            "--json" => output_json = true,
            "--battery" | "-b" => {
                i += 1;
                if i < flag_args.len() {
                    battery_name = flag_args[i].to_string();
                }
            }
            "--category" | "-c" => {
                i += 1;
                if i < flag_args.len() {
                    config.categories.push(flag_args[i].to_string());
                }
            }
            "--param-set" | "-p" => {
                i += 1;
                if i < flag_args.len() {
                    config.parameter_sets.push(flag_args[i].to_string());
                }
            }
            "--filter" | "-f" => {
                i += 1;
                if i < flag_args.len() {
                    config.filter = Some(flag_args[i].to_string());
                }
            }
            "--timeout" | "-t" => {
                i += 1;
                if i < flag_args.len() {
                    timeout_secs = flag_args[i].parse().unwrap_or(30);
                }
            }
            other => {
                eprintln!("Unknown flag: {other}");
                process::exit(1);
            }
        }
        i += 1;
    }

    // Spawn the harness.
    eprintln!("Spawning harness: {harness_cmd}");
    let mut harness = match Harness::spawn(
        harness_cmd,
        &harness_args,
        Duration::from_secs(timeout_secs),
    ) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to start harness: {e}");
            process::exit(1);
        }
    };

    eprintln!(
        "Connected to: {} (functions: {})",
        harness.implementation,
        harness.supported_functions.join(", ")
    );

    // Build the battery.
    let battery: Battery = match battery_name.as_str() {
        "ml-kem" => ml_kem_battery(),
        "ml-dsa" => ml_dsa_battery(),
        other => {
            eprintln!("Unknown battery: {other}. Available: ml-kem, ml-dsa");
            process::exit(1);
        }
    };

    // Run.
    eprintln!("Running {} battery...", battery.name);
    let report = orchestrator::run_battery(&battery, &mut harness, &config);

    // Output.
    if output_json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.to_human());
    }

    // Shutdown.
    if let Err(e) = harness.shutdown() {
        eprintln!("Warning: harness shutdown: {e}");
    }

    // Exit code: 0 if all pass, 1 if any failures.
    if report.summary.failed > 0 || report.summary.errors > 0 {
        process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "Crucible — Cryptographic implementation conformance testing

USAGE:
    crucible <harness-command> [harness-args...] [OPTIONS]

OPTIONS:
    --battery, -b NAME  Battery to run: ml-kem (default) or ml-dsa
    --json              Output results as JSON (default: human-readable)
    --category, -c CAT  Only run tests from category CAT (repeatable)
    --param-set, -p PS  Only run against parameter set PS (repeatable)
    --filter, -f STR    Only run tests whose ID contains STR
    --timeout, -t SECS  Harness spawn timeout in seconds (default: 30)

EXAMPLES:
    crucible ./my-harness
    crucible ./my-harness --battery ml-dsa
    crucible ./my-harness --json --param-set ML-KEM-768
    crucible ./my-harness --category compression --category ntt"
    );
}
