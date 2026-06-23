//! cisbench CLI (Rust port). Mirrors the passive `scan` and `list` surface of
//! the Python reference tool. Passive and offline only — never connects to a
//! database.
//!
//!   cisbench scan <inventory.json> [--json]
//!   cisbench list [--json]

use std::process::exit;

use cisbench::baseline::builtin_profile;
use cisbench::{load_inventory, report_to_json, scan};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    exit(run(&args));
}

fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: cisbench <scan|list> [args]");
        return 2;
    }
    let json_out = args.iter().any(|a| a == "--json");
    let positional: Vec<&String> =
        args[1..].iter().filter(|a| !a.starts_with("--")).collect();

    match args[0].as_str() {
        "list" => {
            let prof = builtin_profile();
            if json_out {
                println!("{}", serde_json::to_string_pretty(&prof).unwrap());
                return 0;
            }
            println!(
                "Profile: {} (v{}) - {} checks",
                prof.name,
                prof.version,
                prof.checks.len()
            );
            for c in &prof.checks {
                println!("{:<10} [{:<8}] {}", c.id, c.severity, c.title);
            }
            0
        }
        "scan" => {
            if positional.is_empty() {
                eprintln!("error: scan requires an inventory path");
                return 2;
            }
            let inv = match load_inventory(positional[0]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            };
            let report = scan(&builtin_profile(), &inv);
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report_to_json(&report)).unwrap()
                );
            } else {
                println!(
                    "\ncisbench scan - profile: {} (v{})",
                    report.profile.name, report.profile.version
                );
                println!("{}", "=".repeat(72));
                for r in &report.results {
                    let status = if r.passed { "PASS" } else { "FAIL" };
                    println!("[{status}] {:<8} {}", r.check.id, r.check.title);
                    println!("        evidence: {}", r.evidence);
                }
                println!("{}", "-".repeat(72));
                println!(
                    "{}/{} passed  |  score {:.1}%  |  weighted {:.1}%",
                    report.passed(),
                    report.total(),
                    report.score(),
                    report.weighted_score()
                );
            }
            0
        }
        other => {
            eprintln!("unknown command {other}");
            2
        }
    }
}
