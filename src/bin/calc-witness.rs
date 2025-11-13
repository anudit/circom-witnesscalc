use std::env;
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use circom_witnesscalc::calc_witness;

struct Args {
    wcd_file: String,
    inputs_file: String,
    witness_file: String,
}

fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();
    let mut wcd_file: Option<String> = None;
    let mut inputs_file: Option<String> = None;
    let mut wtns_file: Option<String> = None;

    let usage = |err_msg: &str| {
        if !err_msg.is_empty() {
            eprintln!("ERROR:");
            eprintln!("    {}", err_msg);
            eprintln!();
        }
        eprintln!("USAGE:");
        eprintln!("    {} <wcd_file> <inputs_json> <wtns_file> [OPTIONS]", args[0]);
        eprintln!();
        eprintln!("ARGUMENTS:");
        eprintln!("    <wcd_file>     Path to the WCD file with compiled bytecode");
        eprintln!("    <inputs_json>  JSON file containing inputs for the circuit");
        eprintln!("    <wtns_file>    File where the witness will be saved");
        eprintln!();
        eprintln!("OPTIONS:");
        eprintln!("    -h | --help                Display this help message");
        let exit_code = if !err_msg.is_empty() { 1i32 } else { 0i32 };
        std::process::exit(exit_code);
    };

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--help" || args[i] == "-h" {
            usage("");
        } else if args[i].starts_with("-") {
            usage(format!("Unknown option: {}", args[i]).as_str());
        } else if wcd_file.is_none() {
            wcd_file = Some(args[i].clone());
        } else if inputs_file.is_none() {
            inputs_file = Some(args[i].clone());
        } else if wtns_file.is_none() {
            wtns_file = Some(args[i].clone());
        } else {
            usage(format!("Unknown argument: {}", args[i]).as_str());
        }
        i += 1;
    }

    Args {
        wcd_file: wcd_file.unwrap_or_else(|| { usage("missing WCD file"); String::new() }),
        inputs_file: inputs_file.unwrap_or_else(|| { usage("missing inputs file"); String::new() }),
        witness_file: wtns_file.unwrap_or_else(|| { usage("missing output .wtns file"); String::new() }),
    }
}

fn main() {
    let args = parse_args();

    let inputs_data = std::fs::read_to_string(&args.inputs_file)
        .expect("Failed to read inputs file");

    let wcd_data = std::fs::read(&args.wcd_file)
        .expect("Failed to read wcd file");

    let start = Instant::now();

    let wtns_bytes = calc_witness(&inputs_data, &wcd_data).unwrap();

    let duration = start.elapsed();
    println!("Witness generated in: {:?}", duration);

    {
        let mut f = File::create(&args.witness_file).unwrap();
        f.write_all(&wtns_bytes).unwrap();
    }

    println!("witness saved to {}", &args.witness_file);
}
