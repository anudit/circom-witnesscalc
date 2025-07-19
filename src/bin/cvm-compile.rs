use std::{env, fs, process};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, Write};
use std::path::Path;
use num_bigint::BigUint;
use num_traits::{Num, ToBytes};
use wtns_file::FieldElement;
use circom_witnesscalc::{ast, vm2, wtns_from_witness2};
use circom_witnesscalc::ast::{Expr, FfExpr, I64Expr, Statement};
use circom_witnesscalc::field::{bn254_prime, Field, FieldOperations, FieldOps, U254};
use circom_witnesscalc::parser::parse;
use circom_witnesscalc::vm2::{disassemble_instruction, execute, Circuit, Component, OpCode};

struct WantWtns {
    wtns_file: String,
    inputs_file: String,
}

struct Args {
    cvm_file: String,
    output_file: String,
    want_wtns: Option<WantWtns>,
    sym_file: String,
}

#[derive(Debug, thiserror::Error)]
enum CompilationError {
    #[error("Main template ID is not found")]
    MainTemplateIDNotFound,
    #[error("witness signal index is out of bounds")]
    WitnessSignalIndexOutOfBounds,
    #[error("witness signal is not set")]
    WitnessSignalNotSet,
    #[error("incorrect SYM file format: `{0}`")]
    IncorrectSymFileFormat(String),
    #[error("jump offset is too large")]
    JumpOffsetIsTooLarge,
    #[error("[assertion] Loop control stack is empty")]
    LoopControlJumpsEmpty,
    #[error("Bus type `{0}` not found in type definitions")]
    BusTypeNotFound(String),
    #[error("Signal at index {0} not found in sym file")]
    SignalNotFoundInSym(usize),
    #[error("Signal '{0}' does not start with expected component prefix '{1}'")]
    SignalPrefixMismatch(String, String),
    #[error("Invalid array index in signal name '{0}': expected [0] but found '{1}'")]
    InvalidArrayIndex(String, String),
}

#[derive(Debug, thiserror::Error)]
enum RuntimeError {
    #[error("incorrect inputs json file: `{0}`")]
    InvalidSignalsJson(String)
}

fn parse_args() -> Args {
    let mut cvm_file: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut wtns_file: Option<String> = None;
    let mut inputs_file: Option<String> = None;
    let mut sym_file: Option<String> = None;

    let args: Vec<String> = env::args().collect();

    let usage = |err_msg: &str| -> ! {
        if !err_msg.is_empty() {
            eprintln!("ERROR:");
            eprintln!("    {}", err_msg);
            eprintln!();
        }
        eprintln!("USAGE:");
        eprintln!("    {} <cvm_file> <sym_file> <output_path> [OPTIONS]", args[0]);
        eprintln!();
        eprintln!("ARGUMENTS:");
        eprintln!("    <cvm_file>    Path to the CVM file with compiled circuit");
        eprintln!("    <sym_file>    Path to the SYM file with signals description");
        eprintln!("    <output_path> File where the witness will be saved");
        eprintln!();
        eprintln!("OPTIONS:");
        eprintln!("    -h | --help       Display this help message");
        eprintln!("    --wtns            If file is provided, the witness will be calculated and saved in this file. Inputs file MUST be provided as well.");
        eprintln!("    --inputs          File with inputs for the circuit. Required if --wtns is provided.");
        let exit_code = if !err_msg.is_empty() { 1i32 } else { 0i32 };
        std::process::exit(exit_code);
    };

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--help" || args[i] == "-h" {
            usage("");
        } else if args[i] == "--wtns" {
            i += 1;
            if i >= args.len() {
                usage("missing argument for --wtns");
            }
            if wtns_file.is_some() {
                usage("multiple witness files");
            }
            wtns_file = Some(args[i].clone());
        } else if args[i] == "--inputs" {
            i += 1;
            if i >= args.len() {
                usage("missing argument for --inputs");
            }
            if inputs_file.is_some() {
                usage("multiple inputs files");
            }
            inputs_file = Some(args[i].clone());
        } else if args[i].starts_with("-") {
            usage(format!("Unknown option: {}", args[i]).as_str());
        } else if cvm_file.is_none() {
            cvm_file = Some(args[i].clone());
        } else if sym_file.is_none() {
            sym_file = Some(args[i].clone());
        } else if output_file.is_none() {
            output_file = Some(args[i].clone());
        }
        i += 1;
    }

    let want_wtns: Option<WantWtns> = match (inputs_file, wtns_file) {
        (Some(inputs_file), Some(wtns_file)) => {
            Some(WantWtns{ wtns_file, inputs_file })
        }
        (None, None) => None,
        (Some(_), None) => {
            usage("inputs file is provided, but witness file is not");
        }
        (None, Some(_)) => {
            usage("witness file is provided, but inputs file is not");
        }
    };

    Args {
        cvm_file: cvm_file.unwrap_or_else(|| { usage("missing CVM file") }),
        output_file: output_file.unwrap_or_else(|| { usage("missing output file") }),
        want_wtns,
        sym_file: sym_file.unwrap_or_else(|| { usage("missing SYM file") }),
    }
}

fn main() {
    let args = parse_args();

    let program_text = fs::read_to_string(&args.cvm_file).unwrap();
    let program = match parse(&program_text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    println!("number of templates: {}", program.templates.len());
    let bn254 = BigUint::from_str_radix("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10).unwrap();
    if program.prime == bn254 {
        let ff = Field::new(bn254_prime);
        let circuit = compile(&ff, &program, &args.sym_file).unwrap();
        let mut component_tree = build_component_tree(
            &program.templates, circuit.main_template_id);
        disassemble::<U254>(&circuit.templates);
        disassemble::<U254>(&circuit.functions);
        if args.want_wtns.is_some() {
            let sym_content = fs::read_to_string(&args.sym_file).unwrap();
            let main_template = &program.templates[circuit.main_template_id];
            calculate_witness(
                &circuit, &mut component_tree, args.want_wtns.unwrap(),
                &sym_content, main_template, &program.types)
                .unwrap();
        }
    } else {
        eprintln!("ERROR: Unsupported prime field");
        std::process::exit(1);
    }

    println!(
        "OK, output is supposed to be saved in {}, but it is not implemented yet.",
        args.output_file);
}

fn input_signals_info(
    sym_file: &str,
    main_template_id: usize) -> Result<HashMap<String, usize>, Box<dyn Error>> {

    let mut m: HashMap<String, usize> = HashMap::new();
    let file = File::open(Path::new(sym_file))?;
    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let values: Vec<&str> = line.split(',').collect();
        if values.len() != 4 {
            return Err(Box::new(CompilationError::IncorrectSymFileFormat(
                format!("line should consist of 4 values: {}", line))));
        }

        let node_id = values[2].parse::<usize>()
            .map_err(|e| Box::new(
                CompilationError::IncorrectSymFileFormat(
                    format!("node_id should be a number: {}", e))))?;
        if node_id != main_template_id {
            continue
        }

        let signal_idx = values[0].parse::<usize>()
            .map_err(|e| Box::new(
                CompilationError::IncorrectSymFileFormat(
                    format!("signal_idx should be a number: {}", e))))?;

        m.insert(values[3].to_string(), signal_idx);
    }
    Ok(m)
}

/// Create a component tree and returns the component and the number of signals
/// of self and all its children
fn create_component(
    templates: &[ast::Template], template_id: usize,
    signals_start: usize) -> (Component, usize) {

    let t = &templates[template_id];
    let mut next_signal_start = signals_start + t.signals_num;
    let mut components = Vec::with_capacity(t.components.len());
    for cmp_tmpl_id in t.components.iter() {
        components.push(match cmp_tmpl_id {
            None => None,
            Some( tmpl_id ) => {
                let (c, signals_num) = create_component(
                    templates, *tmpl_id, next_signal_start);
                next_signal_start += signals_num;
                Some(Box::new(c))
            }
        });
    }
    (
        Component {
            signals_start,
            template_id,
            components,
            number_of_inputs: t.outputs.len(),
        },
        next_signal_start - signals_start
    )
}

fn build_component_tree(
    templates: &[ast::Template], main_template_id: usize) -> Component {

    create_component(templates, main_template_id, 1).0
}

fn calculate_witness<T: FieldOps>(
    circuit: &Circuit<T>, component_tree: &mut Component,
    want_wtns: WantWtns, sym_content: &str, main_template: &ast::Template,
    types: &[ast::Type]) -> Result<(), Box<dyn Error>> {

    let input_infos = build_input_info_from_sym(sym_content, circuit.main_template_id, main_template, types)?;
    let mut signals = init_signals(
        &want_wtns.inputs_file, circuit.signals_num, &circuit.field,
        types, &input_infos)?;
    execute(circuit, &mut signals, &circuit.field, component_tree)?;
    let wtns_data = witness(
        &signals, &circuit.witness, circuit.field.prime)?;

    let mut file = File::create(Path::new(&want_wtns.wtns_file))?;
    file.write_all(&wtns_data)?;
    file.flush()?;
    println!("Witness saved to {}", want_wtns.wtns_file);
    Ok(())
}

fn parse_signals_json<T: FieldOps, F>(
    inputs_data: &[u8], ff: &F) -> Result<HashMap<String, T>, Box<dyn Error>>
where
    for <'a> &'a F: FieldOperations<Type = T> {

    let v: serde_json::Value = serde_json::from_slice(inputs_data)?;
    let mut records: HashMap<String, T> = HashMap::new();
    visit_inputs_json("", &v, &mut records, ff)?;
    Ok(records)
}

fn visit_inputs_json<T: FieldOps, F>(
    prefix: &str, v: &serde_json::Value, records: &mut HashMap<String, T>,
    ff: &F) -> Result<(), Box<dyn Error>>
where
    for <'a> &'a F: FieldOperations<Type = T> {

    match v {
        serde_json::Value::Null => return Err(Box::new(
            RuntimeError::InvalidSignalsJson(
                format!("unexpected null value at path {}", prefix)))),
        serde_json::Value::Bool(b) => {
            let b = if *b { T::one() } else { T::zero() };
            if prefix.is_empty() {
                return Err(Box::new(
                    RuntimeError::InvalidSignalsJson(
                        "boolean value cannot be at the root".to_string())));
            }
            records.insert(prefix.to_string(), b);
        },
        serde_json::Value::Number(n) => {
            let v = if n.is_u64() {
                let n = n.as_u64().unwrap();
                ff.parse_le_bytes(n.to_le_bytes().as_slice())?
            } else if n.is_i64() {
                let n = n.as_i64().unwrap();
                ff.parse_str(&n.to_string())?
            } else {
                return Err(Box::new(RuntimeError::InvalidSignalsJson(
                    format!("invalid number at path {}: {}", prefix, n))));
            };
            if prefix.is_empty() {
                return Err(Box::new(
                    RuntimeError::InvalidSignalsJson(
                        "number value cannot be at the root".to_string())));
            }
            records.insert(prefix.to_string(), v);
        },
        serde_json::Value::String(s) => {
            if prefix.is_empty() {
                return Err(Box::new(
                    RuntimeError::InvalidSignalsJson(
                        "string value cannot be at the root".to_string())));
            }
            records.insert(prefix.to_string(), ff.parse_str(s)?);
        },
        serde_json::Value::Array(vs) => {
            if prefix.is_empty() {
                return Err(Box::new(
                    RuntimeError::InvalidSignalsJson(
                        "array value cannot be at the root".to_string())));
            }
            for (i, v) in vs.iter().enumerate() {
                let new_prefix = format!("{}[{}]", prefix, i);
                visit_inputs_json(&new_prefix, v, records, ff)?;
            }
        },
        serde_json::Value::Object(o) => {
            for (k, v) in o.iter() {
                let new_prefix = if prefix.is_empty() {
                    k.to_string()
                } else {
                    format!("{}.{}", prefix, k)
                };
                visit_inputs_json(&new_prefix, v, records, ff)?;
            }
        },
    };

    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
struct InputInfo {
    name: String,
    offset: usize,
    lengths: Vec<usize>,
    type_id: Option<String>,
}


#[derive(Debug)]
struct SymEntry {
    signal_idx: usize,
    signal_name: String,
}

fn parse_sym_file(sym_content: &str, main_template_id: usize) -> Result<Vec<SymEntry>, Box<dyn Error>> {
    let mut entries = Vec::new();

    for line in sym_content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() != 4 {
            return Err(Box::new(CompilationError::IncorrectSymFileFormat(
                format!("line should consist of 4 values: {}", line))));
        }

        let signal_idx = parts[0].parse::<usize>()
            .map_err(|e| Box::new(CompilationError::IncorrectSymFileFormat(
                format!("signal_idx should be a number: {}", e))))?;

        let template_id = parts[2].parse::<usize>()
            .map_err(|e| Box::new(CompilationError::IncorrectSymFileFormat(
                format!("template_id should be a number: {}", e))))?;

        if template_id != main_template_id {
            continue; // Only include entries for the main template
        }

        let signal_name = parts[3].to_string();

        entries.push(SymEntry {
            signal_idx,
            signal_name,
        });
    }

    Ok(entries)
}

/// Parse a signal name to extract the base name and validate array index
fn parse_signal_name(name_part: &str) -> Result<String, CompilationError> {
    // Check if there's a bracket in the name
    if let Some(bracket_idx) = name_part.find('[') {
        let before_bracket = &name_part[..bracket_idx];
        let after_bracket = &name_part[bracket_idx..];

        // Validate that the array index is [0]
        if !after_bracket.starts_with("[0]") {
            // Extract the actual bracket content for the error message
            let closing_bracket = after_bracket.find(']').unwrap_or(after_bracket.len());
            let bracket_content = &after_bracket[..closing_bracket + 1.min(after_bracket.len())];
            return Err(CompilationError::InvalidArrayIndex(
                name_part.to_string(),
                bracket_content.to_string(),
            ));
        }

        Ok(extract_base_name(before_bracket))
    } else {
        // No bracket - just extract base name before any dots
        Ok(extract_base_name(name_part))
    }
}

/// Extract the base name before the first dot (if any)
fn extract_base_name(name: &str) -> String {
    name.split('.').next().unwrap_or(name).to_string()
}

fn build_input_info_from_sym(
    sym_content: &str,
    main_template_id: usize,
    main_template: &ast::Template,
    types: &[ast::Type],
) -> Result<Vec<InputInfo>, Box<dyn Error>> {
    let sym_entries = parse_sym_file(sym_content, main_template_id)?;

    let component_name_prefix = extract_component_prefix(&sym_entries)?;

    // Calculate the number of output signals to skip
    let outputs_count = calculate_outputs_count(&main_template.outputs, types)?;

    let mut input_infos = Vec::new();
    let mut current_offset = outputs_count + 1; // signal #0 is always 1

    // Process each input signal
    for input in &main_template.inputs {
        // Find the signal entry at the current offset
        let entry = find_signal_entry(&sym_entries, current_offset)?;

        // Verify signal starts with expected component prefix
        if !entry.signal_name.starts_with(&component_name_prefix) {
            return Err(Box::new(CompilationError::SignalPrefixMismatch(
                entry.signal_name.clone(),
                component_name_prefix.clone(),
            )));
        }

        let name_part = &entry.signal_name[component_name_prefix.len()..];
        let base_name = parse_signal_name(name_part)?;

        let lengths = match input {
            ast::Signal::Ff(dims) => dims.to_vec(),
            ast::Signal::Bus(_, dims) => dims.to_vec(),
        };

        // Create the input info
        input_infos.push(InputInfo {
            name: base_name,
            offset: current_offset,
            lengths,
            type_id: match input {
                ast::Signal::Ff(_) => None,
                ast::Signal::Bus(bus_type, _) => Some(bus_type.clone()),
            },
        });

        // Calculate signal size and advance offset
        current_offset += calculate_signal_size(input, types)?;
    }

    Ok(input_infos)
}

/// Extract component prefix from the first sym entry
fn extract_component_prefix(sym_entries: &[SymEntry]) -> Result<String, Box<dyn Error>> {
    let first_entry = sym_entries.first()
        .ok_or_else(|| Box::new(CompilationError::IncorrectSymFileFormat(
            "No sym entries found for main template".to_string())))?;

    let signal_name = &first_entry.signal_name;
    let dot_idx = signal_name.find('.')
        .ok_or_else(|| Box::new(CompilationError::IncorrectSymFileFormat(
            format!("Expected signal name with component prefix, got: {}", signal_name))))?;

    Ok(format!("{}.", &signal_name[..dot_idx]))
}

/// Calculate total number of output signals
fn calculate_outputs_count(outputs: &[ast::Signal], types: &[ast::Type]) -> Result<usize, Box<dyn Error>> {
    let mut count = 0;
    for signal in outputs {
        count += calculate_signal_size(signal, types)?;
    }
    Ok(count)
}

/// Calculate the size of a signal (number of elements)
fn calculate_signal_size(signal: &ast::Signal, types: &[ast::Type]) -> Result<usize, Box<dyn Error>> {
    match signal {
        ast::Signal::Ff(dims) => {
            Ok(if dims.is_empty() { 1 } else { dims.iter().product() })
        }
        ast::Signal::Bus(bus_type, dims) => {
            let type_def = types.iter().find(|t| t.name == *bus_type)
                .ok_or_else(|| Box::new(CompilationError::BusTypeNotFound(bus_type.clone())))?;
            let base_size = calculate_bus_size(type_def, types);
            Ok(if dims.is_empty() { base_size } else { base_size * dims.iter().product::<usize>() })
        }
    }
}

/// Find signal entry at specific index
fn find_signal_entry(sym_entries: &[SymEntry], signal_idx: usize) -> Result<&SymEntry, Box<dyn Error>> {
    sym_entries.iter()
        .find(|e| e.signal_idx == signal_idx)
        .ok_or_else(|| Box::new(CompilationError::SignalNotFoundInSym(signal_idx)) as Box<dyn Error>)
}


fn calculate_bus_size(bus_type: &ast::Type, _all_types: &[ast::Type]) -> usize {
    let mut total_size = 0;

    for field in &bus_type.fields {
        // The size field already contains the total size for this field
        total_size += field.size;
    }

    total_size
}

/// Expand an InputInfo into all its constituent signal paths with their indices
fn expand_input_info_to_signal_paths(
    input_info: &InputInfo,
    types: &[ast::Type]
) -> Result<Vec<(String, usize)>, Box<dyn Error>> {
    let mut paths = Vec::new();
    let mut current_offset = input_info.offset;

    if let Some(type_id) = &input_info.type_id {
        // This is a bus type - expand it recursively
        let bus_type = types.iter().find(|t| t.name == *type_id)
            .ok_or_else(|| Box::new(CompilationError::BusTypeNotFound(type_id.clone())))?;

        if input_info.lengths.is_empty() {
            // Single bus instance
            expand_bus_type(&input_info.name, bus_type, types, &mut current_offset, &mut paths)?;
        } else {
            // Array of bus instances
            let total_elements: usize = input_info.lengths.iter().product();
            for i in 0..total_elements {
                let array_path = format!("{}[{}]", input_info.name, i);
                expand_bus_type(&array_path, bus_type, types, &mut current_offset, &mut paths)?;
            }
        }
    } else {
        // This is a field (ff) type
        if input_info.lengths.is_empty() {
            // Single field
            paths.push((input_info.name.clone(), current_offset));
        } else {
            // Array of fields - generate multi-dimensional paths
            let total_elements: usize = input_info.lengths.iter().product();
            for i in 0..total_elements {
                let multi_indices = flat_to_multidim_indices(i, &input_info.lengths);
                let mut array_path = input_info.name.clone();
                for idx in multi_indices {
                    array_path.push_str(&format!("[{}]", idx));
                }
                paths.push((array_path, current_offset));
                current_offset += 1;
            }
        }
    }

    Ok(paths)
}

/// Recursively expand a bus type into individual field paths
fn expand_bus_type(
    base_path: &str,
    bus_type: &ast::Type,
    types: &[ast::Type],
    current_offset: &mut usize,
    paths: &mut Vec<(String, usize)>
) -> Result<(), Box<dyn Error>> {
    for field in &bus_type.fields {
        let field_path = format!("{}.{}", base_path, field.name);

        match &field.kind {
            ast::TypeFieldKind::Bus(bus_type_name) => {
                // This field is another bus type
                let field_type = types.iter().find(|t| t.name == *bus_type_name)
                    .ok_or_else(|| Box::new(CompilationError::BusTypeNotFound(bus_type_name.to_string())))?;

                if field.dims.is_empty() {
                    // Single bus instance
                    expand_bus_type(&field_path, field_type, types, current_offset, paths)?;
                } else {
                    // Array of bus instances
                    let total_elements: usize = field.dims.iter().product();
                    for i in 0..total_elements {
                        let array_path = format!("{}[{}]", field_path, i);
                        expand_bus_type(&array_path, field_type, types, current_offset, paths)?;
                    }
                }
            },
            ast::TypeFieldKind::Ff => {
                // This field is a primitive type (ff)
                if field.dims.is_empty() {
                    // Single field
                    paths.push((field_path, *current_offset));
                    *current_offset += 1;
                } else {
                    // Array of fields
                    let total_elements: usize = field.dims.iter().product();
                    for i in 0..total_elements {
                        let array_path = format!("{}[{}]", field_path, i);
                        paths.push((array_path, *current_offset));
                        *current_offset += 1;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Convert flat array index to multi-dimensional indices
fn flat_to_multidim_indices(flat_idx: usize, dimensions: &[usize]) -> Vec<usize> {
    let mut indices = Vec::new();
    let mut remaining = flat_idx;

    for &dim in dimensions.iter().rev() {
        indices.push(remaining % dim);
        remaining /= dim;
    }

    indices.reverse();
    indices
}

/// Check if a path represents a flat array access and convert to multi-dimensional path
fn try_convert_flat_to_multidim_path(
    path: &str,
    input_infos: &[InputInfo]
) -> Option<String> {
    // Extract base name and flat index from path like "b[4]"
    if let Some(bracket_start) = path.find('[') {
        let base_name = &path[..bracket_start];
        let bracket_part = &path[bracket_start..];

        // Parse flat index from "[4]"
        if let Some(flat_idx_str) = bracket_part.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if let Ok(flat_idx) = flat_idx_str.parse::<usize>() {
                // Find matching input info
                for input_info in input_infos {
                    if input_info.name == base_name && input_info.lengths.len() > 1 {
                        // Convert flat index to multi-dimensional indices
                        let multi_indices = flat_to_multidim_indices(flat_idx, &input_info.lengths);

                        // Build multi-dimensional path
                        let mut result = base_name.to_string();
                        for idx in multi_indices {
                            result.push_str(&format!("[{}]", idx));
                        }
                        return Some(result);
                    }
                }
            }
        }
    }

    None
}

fn init_signals<T: FieldOps, F>(
    inputs_file: &str, signals_num: usize, ff: &F, types: &[ast::Type],
    input_infos: &[InputInfo]) -> Result<Vec<Option<T>>, Box<dyn Error>>
where
    for <'a> &'a F: FieldOperations<Type = T> {

    let mut signals = vec![None; signals_num];
    signals[0] = Some(T::one());

    // Expand each InputInfo into all its constituent signal paths
    let mut signal_path_to_idx: HashMap<String, usize> = HashMap::new();
    for input_info in input_infos {
        let expanded_paths = expand_input_info_to_signal_paths(input_info, types)?;
        for (path, idx) in expanded_paths {
            signal_path_to_idx.insert(path, idx);
        }
    }

    let inputs_data = fs::read_to_string(inputs_file)?;
    let input_signals = parse_signals_json(inputs_data.as_bytes(), ff)?;

    for (path, value) in input_signals.iter() {
        // Try to find exact match first
        if let Some(&signal_idx) = signal_path_to_idx.get(path) {
            signal_path_to_idx.remove(path);
            signals[signal_idx] = Some(*value);
            continue;
        }

        // Try converting flat array path to multi-dimensional path
        if let Some(multidim_path) = try_convert_flat_to_multidim_path(path, input_infos) {
            if let Some(&signal_idx) = signal_path_to_idx.get(&multidim_path) {
                signal_path_to_idx.remove(&multidim_path);
                signals[signal_idx] = Some(*value);
                continue;
            }
        }

        // Try parsing as array access with [0] suffix for backwards compatibility
        if path.ends_with("[0]") {
            let base_path = path.trim_end_matches("[0]");
            if let Some(&signal_idx) = signal_path_to_idx.get(base_path) {
                signal_path_to_idx.remove(base_path);
                signals[signal_idx] = Some(*value);
                continue;
            }
        }

        return Err(Box::new(
            RuntimeError::InvalidSignalsJson(
                format!("signal {} is not found in input mapping", path))));
    }

    // Check if any input signals were not provided
    if !signal_path_to_idx.is_empty() {
        let missing_signals: Vec<String> = signal_path_to_idx.keys().cloned().collect();
        return Err(Box::new(
            RuntimeError::InvalidSignalsJson(
                format!("Missing input signals: {}", missing_signals.join(", ")))));
    }

    Ok(signals)
}

fn witness<T: FieldOps>(signals: &[Option<T>], witness_signals: &[usize], prime: T) -> Result<Vec<u8>, CompilationError> {
    let mut result = Vec::with_capacity(witness_signals.len());

    for &idx in witness_signals {
        if idx >= signals.len() {
            return Err(CompilationError::WitnessSignalIndexOutOfBounds)
        }

        match signals[idx] {
            Some(s) => result.push(s),
            None => return Err(CompilationError::WitnessSignalNotSet)
        }
    }

    match T::BYTES {
        8 => {
            let vec_witness: Vec<FieldElement<8>> = result
                .iter()
                .map(|a| {
                    let a: [u8; 8] = a.to_le_bytes().try_into().unwrap();
                    a.into()
                })
                .collect();
            Ok(wtns_from_witness2(vec_witness, prime))
        }
        32 => {
            let vec_witness: Vec<FieldElement<32>> = result
                .iter()
                .map(|a| {
                    let a: [u8; 32] = a.to_le_bytes().try_into().unwrap();
                    a.into()
                })
                .collect();
            Ok(wtns_from_witness2(vec_witness, prime))
        }
        _ => {
            Err(CompilationError::WitnessSignalNotSet)
        }
    }

}

fn disassemble<T: FieldOps>(templates: &[vm2::Template]) {
    for t in templates.iter() {
        println!("[begin]Template: {}", t.name);
        let mut ip: usize = 0;
        while ip < t.code.len() {
            ip = disassemble_instruction::<T>(
                &t.code, ip, &t.name, &t.ff_variable_names,
                &t.i64_variable_names);
        }
        println!("[end]")
    }
}

fn compile<T: FieldOps>(
    ff: &Field<T>, tree: &ast::AST, sym_file: &str) -> Result<Circuit<T>, Box<dyn Error>>
where {

    // First, compile functions and build function registry
    let mut functions = Vec::new();
    let mut function_registry = HashMap::new();

    for (i, f) in tree.functions.iter().enumerate() {
        let compiled_function = compile_function(f, ff, &function_registry)?;
        function_registry.insert(f.name.clone(), i);
        functions.push(compiled_function);
    }

    // Then compile templates with the function registry
    let mut templates = Vec::new();

    for t in tree.templates.iter() {
        let compiled_template = compile_template(t, ff, &function_registry)?;
        templates.push(compiled_template);
        // println!("Template: {}", t.name);
        // println!("Compiled code len: {}", compiled_template.code.len());
    }

    let mut main_template_id = None;
    for (i, t) in templates.iter().enumerate() {
        if t.name == tree.start {
            main_template_id = Some(i)
        }
    }

    let main_template_id = main_template_id
        .ok_or(CompilationError::MainTemplateIDNotFound)?;

    Ok(Circuit {
        main_template_id,
        templates,
        functions,
        function_registry,
        field: ff.clone(),
        witness: tree.witness.clone(),
        input_signals_info: input_signals_info(sym_file, main_template_id)?,
        signals_num: tree.signals,
    })
}

#[derive(Debug, Clone, Copy)]
enum VariableType {
    Ff,
    I64,
}

struct TemplateCompilationContext<'a> {
    code: Vec<u8>,
    ff_variable_indexes: HashMap<String, i64>,
    i64_variable_indexes: HashMap<String, i64>,
    // Registry to track variable types
    variable_types: HashMap<String, VariableType>,
    // Stack of loop render frames.
    // * The first element of the tuple is the position of the first loop body
    // instruction (the continue statement).
    // * The second element is a vector of indexes where to inject the
    // position after loop body (the break statement)
    loop_control_jumps: Vec<(usize, Vec<usize>)>,
    // Function registry for resolving function names to indices
    function_registry: &'a HashMap<String, usize>,
}

impl<'a> TemplateCompilationContext<'a> {
    fn new(function_registry: &'a HashMap<String, usize>) -> Self {
        Self {
            code: vec![],
            ff_variable_indexes: HashMap::new(),
            i64_variable_indexes: HashMap::new(),
            variable_types: HashMap::new(),
            loop_control_jumps: vec![],
            function_registry,
        }
    }

    fn get_ff_variable_index(&mut self, var_name: &str) -> i64 {
        // Register the variable type
        self.variable_types.insert(var_name.to_string(), VariableType::Ff);
        
        let next_idx = self.ff_variable_indexes.len() as i64;
        *self.ff_variable_indexes
            .entry(var_name.to_string()).or_insert(next_idx)
    }
    fn get_i64_variable_index(&mut self, var_name: &str) -> i64 {
        // Register the variable type
        self.variable_types.insert(var_name.to_string(), VariableType::I64);
        
        let next_idx = self.i64_variable_indexes.len() as i64;
        *self.i64_variable_indexes
            .entry(var_name.to_string()).or_insert(next_idx)
    }
}

fn operand_i64<'a>(
    ctx: &mut TemplateCompilationContext<'a>, operand: &ast::I64Operand) {

    match operand {
        ast::I64Operand::Literal(v) => {
            ctx.code.push(OpCode::PushI64 as u8);
            ctx.code.extend_from_slice(v.to_le_bytes().as_slice());
        }
        ast::I64Operand::Variable(var_name) => {
            let var_idx = ctx.get_i64_variable_index(var_name);
            ctx.code.push(OpCode::LoadVariableI64 as u8);
            ctx.code.extend_from_slice(var_idx.to_le_bytes().as_slice());
        }
    }
}

fn i64_expression<'a, F>(
    ctx: &mut TemplateCompilationContext<'a>, ff: &F,
    expr: &I64Expr) -> Result<(), Box<dyn Error>>
where
    for <'b> &'b F: FieldOperations {
    
    match expr {
        I64Expr::Variable(var_name) => {
            let var_idx = ctx.get_i64_variable_index(var_name);
            ctx.code.push(OpCode::LoadVariableI64 as u8);
            ctx.code.extend_from_slice(var_idx.to_le_bytes().as_slice());
        }
        I64Expr::Literal(value) => {
            ctx.code.push(OpCode::PushI64 as u8);
            ctx.code.extend_from_slice(value.to_le_bytes().as_slice());
        }
        I64Expr::Add(lhs, rhs) => {
            i64_expression(ctx, ff, rhs)?;
            i64_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpI64Add as u8);
        }
        I64Expr::Sub(lhs, rhs) => {
            i64_expression(ctx, ff, rhs)?;
            i64_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpI64Sub as u8);
        }
        I64Expr::Mul(lhs, rhs) => {
            i64_expression(ctx, ff, rhs)?;
            i64_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpI64Mul as u8);
        }
        I64Expr::Lte(lhs, rhs) => {
            i64_expression(ctx, ff, rhs)?;
            i64_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpI64Lte as u8);
        }
        I64Expr::Load(addr) => {
            operand_i64(ctx, addr);
            ctx.code.push(OpCode::I64Load as u8);
        }
        I64Expr::Wrap(ff_expr) => {
            ff_expression(ctx, ff, ff_expr)?;
            ctx.code.push(OpCode::I64WrapFf as u8);
        }
    }
    Ok(())
}

fn ff_expression<'a, F>(
    ctx: &mut TemplateCompilationContext<'a>, ff: &F,
    expr: &FfExpr) -> Result<(), Box<dyn Error>>
where
    for <'b> &'b F: FieldOperations {

    match expr {
        FfExpr::GetSignal(operand) => {
            operand_i64(ctx, operand);
            ctx.code.push(OpCode::LoadSignal as u8);
        }
        FfExpr::GetCmpSignal{ cmp_idx, sig_idx } => {
            operand_i64(ctx, cmp_idx);
            operand_i64(ctx, sig_idx);
            ctx.code.push(OpCode::LoadCmpSignal as u8);
        }
        FfExpr::FfMul(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpMul as u8);
        },
        FfExpr::FfAdd(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpAdd as u8);
        },
        FfExpr::FfNeq(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpNeq as u8);
        },
        FfExpr::FfDiv(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpDiv as u8);
        },
        FfExpr::FfSub(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpSub as u8);
        },
        FfExpr::FfEq(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpEq as u8);
        },
        FfExpr::FfEqz(lhs) => {
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpEqz as u8);
        },
        FfExpr::Variable( var_name ) => {
            let var_idx = ctx.get_ff_variable_index(var_name);
            ctx.code.push(OpCode::LoadVariableFf as u8);
            ctx.code.extend_from_slice(var_idx.to_le_bytes().as_slice());
        },
        FfExpr::Literal(v) => {
            ctx.code.push(OpCode::PushFf as u8);
            let x = ff.parse_le_bytes(v.to_le_bytes().as_slice())?;
            ctx.code.extend_from_slice(x.to_le_bytes().as_slice());
        },
        FfExpr::Load(idx) => {
            operand_i64(ctx, idx);
            ctx.code.push(OpCode::FfLoad as u8);
        },
        FfExpr::Lt(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpLt as u8);
        },
        FfExpr::FfShr(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpShr as u8);
        },
        FfExpr::FfBand(lhs, rhs) => {
            ff_expression(ctx, ff, rhs)?;
            ff_expression(ctx, ff, lhs)?;
            ctx.code.push(OpCode::OpBand as u8);
        },
        FfExpr::Rem(_lhs, _rhs) => {
            todo!();
        },
    };
    Ok(())
}

fn compile_assignment<'a, F>(
    ctx: &mut TemplateCompilationContext<'a>, ff: &F,
    name: &str, value: &Expr) -> Result<(), Box<dyn Error>>
where
    for <'b> &'b F: FieldOperations {
    
    match value {
        Expr::Ff(ff_expr) => {
            ff_expression(ctx, ff, ff_expr)?;
            ctx.code.push(OpCode::StoreVariableFf as u8);
            let var_idx = ctx.get_ff_variable_index(name);
            ctx.code.extend_from_slice(var_idx.to_le_bytes().as_slice());
        }
        Expr::I64(i64_expr) => {
            i64_expression(ctx, ff, i64_expr)?;
            ctx.code.push(OpCode::StoreVariableI64 as u8);
            let var_idx = ctx.get_i64_variable_index(name);
            ctx.code.extend_from_slice(var_idx.to_le_bytes().as_slice());
        }
        Expr::Variable(source_var) => {
            // Check the type of the source variable
            match ctx.variable_types.get(source_var) {
                Some(VariableType::Ff) => {
                    // Load from FF variable and store to FF variable
                    let source_idx = ctx.get_ff_variable_index(source_var);
                    ctx.code.push(OpCode::LoadVariableFf as u8);
                    ctx.code.extend_from_slice(source_idx.to_le_bytes().as_slice());

                    ctx.code.push(OpCode::StoreVariableFf as u8);
                    let dest_idx = ctx.get_ff_variable_index(name);
                    ctx.code.extend_from_slice(dest_idx.to_le_bytes().as_slice());
                }
                Some(VariableType::I64) => {
                    // Load from I64 variable and store to I64 variable
                    let source_idx = ctx.get_i64_variable_index(source_var);
                    ctx.code.push(OpCode::LoadVariableI64 as u8);
                    ctx.code.extend_from_slice(source_idx.to_le_bytes().as_slice());

                    ctx.code.push(OpCode::StoreVariableI64 as u8);
                    let dest_idx = ctx.get_i64_variable_index(name);
                    ctx.code.extend_from_slice(dest_idx.to_le_bytes().as_slice());
                }
                None => {
                    return Err(format!("Variable '{}' not found in type registry", source_var).into());
                }
            }
        }
    }
    Ok(())
}

fn instruction<'a, F>(
    ctx: &mut TemplateCompilationContext<'a>, ff: &F,
    stmt: &ast::Statement) -> Result<(), Box<dyn Error>>
where
    for <'b> &'b F: FieldOperations {

    match stmt {
        Statement::SetSignal { idx, value } => {
            ff_expression(ctx, ff, value)?;
            operand_i64(ctx, idx);
            ctx.code.push(OpCode::StoreSignal as u8);
        },
        Statement::FfStore { idx, value } => {
            ff_expression(ctx, ff, value)?;
            operand_i64(ctx, idx);
            ctx.code.push(OpCode::FfStore as u8);
        },
        Statement::SetCmpSignalRun { cmp_idx, sig_idx, value } => {
            operand_i64(ctx, cmp_idx);
            operand_i64(ctx, sig_idx);
            ff_expression(ctx, ff, value)?;
            ctx.code.push(OpCode::StoreCmpSignalAndRun as u8);
        },
        Statement::SetCmpInputCntCheck { .. } => {
            todo!();
        },
        Statement::SetCmpInput { cmp_idx, sig_idx, value } => {
            i64_expression(ctx, ff, cmp_idx)?;
            i64_expression(ctx, ff, sig_idx)?;
            ff_expression(ctx, ff, value)?;
            ctx.code.push(OpCode::StoreCmpInput as u8);
        },
        Statement::Branch { condition, if_block, else_block } => {
            // Resolve variable references to their typed equivalents
            let resolved_condition: Expr;
            let condition_to_evaluate = if let Expr::Variable(var_name) = condition {
                match ctx.variable_types.get(var_name) {
                    Some(VariableType::Ff) => {
                        resolved_condition = Expr::Ff(FfExpr::Variable(var_name.clone()));
                        &resolved_condition
                    }
                    Some(VariableType::I64) => {
                        resolved_condition = Expr::I64(I64Expr::Variable(var_name.clone()));
                        &resolved_condition
                    }
                    None => {
                        return Err(format!("Variable '{}' not found in type registry", var_name).into());
                    }
                }
            } else {
                condition
            };

            let else_jump_offset = match condition_to_evaluate {
                Expr::Ff(expr) => {
                    ff_expression(ctx, ff, expr)?;
                    pre_emit_jump_if_false(&mut ctx.code, true)
                },
                Expr::I64(expr) => {
                    i64_expression(ctx, ff, expr)?;
                    pre_emit_jump_if_false(&mut ctx.code, false)
                },
                Expr::Variable( .. ) => {
                    panic!("[assertion] expression should be already converted to Ff or I64");
                },
            };

            block(ctx, ff, if_block)?;

            if !else_block.is_empty() {
                // Only emit end jump if the if block doesn't end with return
                let end_jump_offset = pre_emit_jump(&mut ctx.code);

                // Now patch the else_jump to jump to the start of the else block
                let else_start = ctx.code.len();
                patch_jump(&mut ctx.code, else_jump_offset, else_start)?;

                block(ctx, ff, else_block)?;

                let to = ctx.code.len();
                patch_jump(&mut ctx.code, end_jump_offset, to)?;
            } else {
                // No else block, patch to jump to end
                let to = ctx.code.len();
                patch_jump(&mut ctx.code, else_jump_offset, to)?;
            }
        },
        Statement::Loop( loop_block ) => {
            // Start of loop
            let loop_start = ctx.code.len();
            ctx.loop_control_jumps.push((loop_start, vec![]));

            // Compile loop body
            block(ctx, ff, loop_block)?;

            let to = ctx.code.len();
            let (_, break_jumps) = ctx.loop_control_jumps.pop()
                .ok_or(CompilationError::LoopControlJumpsEmpty)?;
            for break_jump_offset in break_jumps {
                patch_jump(&mut ctx.code, break_jump_offset, to)?;
            }
        },
        Statement::Break => {
            let jump_offset = pre_emit_jump(&mut ctx.code);
            if let Some((_, break_jumps)) = ctx.loop_control_jumps.last_mut() {
                break_jumps.push(jump_offset);
            } else {
                return Err(Box::new(CompilationError::LoopControlJumpsEmpty));
            }
        },
        Statement::Continue => {
            let jump_offset = pre_emit_jump(&mut ctx.code);
            patch_jump(&mut ctx.code, jump_offset, ctx.loop_control_jumps.last()
                .ok_or(CompilationError::LoopControlJumpsEmpty)?.0)?;
        },
        Statement::Error { code } => {
            operand_i64(ctx, code);
            ctx.code.push(OpCode::Error as u8);
        },
        Statement::FfMReturn { dst, src, size } => {
            // Push operands in reverse order so they are popped in correct order
            // The VM expects: stack[-2]=dst, stack[-1]=src, stack[0]=size
            operand_i64(ctx, dst);
            operand_i64(ctx, src);
            operand_i64(ctx, size);
            ctx.code.push(OpCode::FfMReturn as u8);
        },
        Statement::FfMCall { name: function_name, args } => {
            // Emit the FfMCall opcode
            ctx.code.push(OpCode::FfMCall as u8);

            // Look up function by name to get its index
            let func_idx = *ctx.function_registry.get(function_name)
                .ok_or_else(|| format!("Function '{}' not found", function_name))?;
            let func_idx: u32 = func_idx.try_into()
                .map_err(|_| "Function index too large")?;
            ctx.code.extend_from_slice(&func_idx.to_le_bytes());

            // Emit argument count
            ctx.code.push(args.len() as u8);

            // Emit each argument
            for arg in args {
                match arg {
                    ast::CallArgument::I64Literal(value) => {
                        ctx.code.push(0); // arg type 0 = i64 literal
                        ctx.code.extend_from_slice(&value.to_le_bytes());
                    }
                    ast::CallArgument::FfLiteral(value) => {
                        ctx.code.push(1); // arg type 1 = ff literal
                        let x = ff.parse_le_bytes(value.to_le_bytes().as_slice())?;
                        ctx.code.extend_from_slice(x.to_le_bytes().as_slice());
                    }
                    ast::CallArgument::Variable(var_name) => {
                        // Look up variable type in registry
                        match ctx.variable_types.get(var_name) {
                            Some(VariableType::Ff) => {
                                ctx.code.push(2); // arg type 2 = ff variable
                                let var_idx = ctx.get_ff_variable_index(var_name);
                                ctx.code.extend_from_slice(&var_idx.to_le_bytes());
                            }
                            Some(VariableType::I64) => {
                                ctx.code.push(3); // arg type 3 = i64 variable
                                let var_idx = ctx.get_i64_variable_index(var_name);
                                ctx.code.extend_from_slice(&var_idx.to_le_bytes());
                            }
                            None => {
                                return Err(format!("Variable '{}' not found in type registry", var_name).into());
                            }
                        }
                    }
                    ast::CallArgument::I64Memory { addr, size } => {
                        // i64.memory uses types 8-11 (base 8 = 0b1000)
                        let mut arg_type = 8u8;

                        // Set bit 0 if addr is a variable
                        if matches!(addr, ast::I64Operand::Variable(_)) {
                            arg_type |= 1;
                        }

                        // Set bit 1 if size is a variable
                        if matches!(size, ast::I64Operand::Variable(_)) {
                            arg_type |= 2;
                        }

                        ctx.code.push(arg_type);

                        match addr {
                            ast::I64Operand::Literal(v) => {
                                ctx.code.extend_from_slice(&v.to_le_bytes());
                            }
                            ast::I64Operand::Variable(var_name) => {
                                let var_idx = ctx.get_i64_variable_index(var_name);
                                ctx.code.extend_from_slice(&var_idx.to_le_bytes());
                            }
                        }
                        match size {
                            ast::I64Operand::Literal(v) => {
                                ctx.code.extend_from_slice(&v.to_le_bytes());
                            }
                            ast::I64Operand::Variable(var_name) => {
                                let var_idx = ctx.get_i64_variable_index(var_name);
                                ctx.code.extend_from_slice(&var_idx.to_le_bytes());
                            }
                        }
                    }
                    ast::CallArgument::FfMemory { addr, size } => {
                        // ff.memory uses types 4-7 (base 4 = 0b0100)
                        let mut arg_type = 4u8;

                        // Set bit 0 if addr is a variable
                        if matches!(addr, ast::I64Operand::Variable(_)) {
                            arg_type |= 1;
                        }

                        // Set bit 1 if size is a variable
                        if matches!(size, ast::I64Operand::Variable(_)) {
                            arg_type |= 2;
                        }

                        ctx.code.push(arg_type);

                        match addr {
                            ast::I64Operand::Literal(v) => {
                                ctx.code.extend_from_slice(&v.to_le_bytes());
                            }
                            ast::I64Operand::Variable(var_name) => {
                                let var_idx = ctx.get_i64_variable_index(var_name);
                                ctx.code.extend_from_slice(&var_idx.to_le_bytes());
                            }
                        }
                        match size {
                            ast::I64Operand::Literal(v) => {
                                ctx.code.extend_from_slice(&v.to_le_bytes());
                            }
                            ast::I64Operand::Variable(var_name) => {
                                let var_idx = ctx.get_i64_variable_index(var_name);
                                ctx.code.extend_from_slice(&var_idx.to_le_bytes());
                            }
                        }
                    }
                }
            }
        }
        Statement::Assignment { name, value } => {
            compile_assignment(ctx, ff, name, value)?;
        }
    }
    Ok(())
}

fn block<'a, F>(
    ctx: &mut TemplateCompilationContext<'a>, ff: &F,
    statements: &[ast::Statement]) -> Result<(), Box<dyn Error>>
where
    for <'b> &'b F: FieldOperations {

    for inst in statements {
        instruction(ctx, ff, inst)?;
    }

    Ok(())
}

fn calc_jump_offset(from: usize, to: usize) -> Result<i32, CompilationError> {
    let from: i64 = from.try_into()
        .map_err(|_| CompilationError::JumpOffsetIsTooLarge)?;
    let to: i64 = to.try_into()
        .map_err(|_| CompilationError::JumpOffsetIsTooLarge)?;

    (to - from).try_into()
        .map_err(|_| CompilationError::JumpOffsetIsTooLarge)
}


/// We expect the jump offset located at `jump_offset_addr` to be 4 bytes long.
/// The jump offset is calculated as `to - jump_offset_addr - 4`.
fn patch_jump(
    code: &mut [u8], jump_offset_addr: usize,
    to: usize) -> Result<(), CompilationError> {

    let offset = calc_jump_offset(jump_offset_addr + 4, to)?;
    code[jump_offset_addr..jump_offset_addr+4].copy_from_slice(offset.to_le_bytes().as_ref());
    Ok(())
}


fn pre_emit_jump_if_false(code: &mut Vec<u8>, is_ff: bool) -> usize {
    if is_ff {
        code.push(OpCode::JumpIfFalseFf as u8);
    } else {
        code.push(OpCode::JumpIfFalseI64 as u8);
    }
    for _ in 0..4 { code.push(0xffu8); }
    code.len() - 4
}

fn pre_emit_jump(code: &mut Vec<u8>) -> usize {
    code.push(OpCode::Jump as u8);
    for _ in 0..4 { code.push(0xffu8); }
    code.len() - 4
}


fn compile_function<F>(
    f: &ast::Function, 
    ff: &F, 
    function_registry: &HashMap<String, usize>
) -> Result<vm2::Template, Box<dyn Error>>
where
    for <'a> &'a F: FieldOperations {

    let mut ctx = TemplateCompilationContext::new(function_registry);
    for i in &f.body {
        instruction(&mut ctx, ff, i)?;
    }

    println!("i64 variables:");
    for (x, y) in ctx.i64_variable_indexes.iter() {
        println!("{} {}", x, y);
    }
    println!("ff variables:");
    for (x, y) in ctx.ff_variable_indexes.iter() {
        println!("{} {}", x, y);
    }

    // Build reverse mappings for variable names (index -> name)
    let mut ff_variable_names = HashMap::new();
    for (name, &index) in &ctx.ff_variable_indexes {
        ff_variable_names.insert(index as usize, name.clone());
    }

    let mut i64_variable_names = HashMap::new();
    for (name, &index) in &ctx.i64_variable_indexes {
        i64_variable_names.insert(index as usize, name.clone());
    }

    Ok(vm2::Template {
        name: f.name.clone(),
        code: ctx.code,
        vars_i64_num: ctx.i64_variable_indexes.len(),
        vars_ff_num: ctx.ff_variable_indexes.len(),
        ff_variable_names,
        i64_variable_names,
    })
}

fn compile_template<F>(
    t: &ast::Template, 
    ff: &F, 
    function_registry: &HashMap<String, usize>
) -> Result<vm2::Template, Box<dyn Error>>
where
    for <'a> &'a F: FieldOperations {

    let mut ctx = TemplateCompilationContext::new(function_registry);
    for i in &t.body {
        instruction(&mut ctx, ff, i)?;
    }

    // Build reverse mappings for variable names (index -> name)
    let mut ff_variable_names = HashMap::new();
    for (name, &index) in &ctx.ff_variable_indexes {
        ff_variable_names.insert(index as usize, name.clone());
    }

    let mut i64_variable_names = HashMap::new();
    for (name, &index) in &ctx.i64_variable_indexes {
        i64_variable_names.insert(index as usize, name.clone());
    }

    Ok(vm2::Template {
        name: t.name.clone(),
        code: ctx.code,
        vars_i64_num: ctx.i64_variable_indexes.len(),
        vars_ff_num: ctx.ff_variable_indexes.len(),
        ff_variable_names,
        i64_variable_names,
    })
}

#[cfg(test)]
mod tests {
    use num_traits::One;
    use circom_witnesscalc::ast::{FfExpr, I64Operand, Signal, Statement, I64Expr, Expr};
    use circom_witnesscalc::vm2::disassemble_instruction_to_string;
    use circom_witnesscalc::field::{bn254_prime, Field};
    use super::*;

    #[test]
    fn test_example() {
        // Placeholder test
    }

    #[test]
    fn test_build_component_tree() {
        // Create leaf templates with no components
        let template1 = ast::Template {
            name: "Leaf1".to_string(),
            outputs: vec![Signal::Ff(vec![1])],
            inputs: vec![Signal::Ff(vec![1])],
            signals_num: 3,
            components: vec![],
            body: vec![],
        };

        let template2 = ast::Template {
            name: "Leaf2".to_string(),
            outputs: vec![Signal::Ff(vec![1])],
            inputs: vec![Signal::Ff(vec![1])],
            signals_num: 3,
            components: vec![],
            body: vec![],
        };

        let template3 = ast::Template {
            name: "Leaf3".to_string(),
            outputs: vec![Signal::Ff(vec![1])],
            inputs: vec![Signal::Ff(vec![1])],
            signals_num: 3,
            components: vec![],
            body: vec![],
        };

        let template4 = ast::Template {
            name: "Leaf4".to_string(),
            outputs: vec![Signal::Ff(vec![1])],
            inputs: vec![Signal::Ff(vec![1])],
            signals_num: 3,
            components: vec![],
            body: vec![],
        };

        // Create middle-level templates, each with two children
        // First middle template has two children
        let template5 = ast::Template {
            name: "Middle1".to_string(),
            outputs: vec![Signal::Ff(vec![1])],
            inputs: vec![Signal::Ff(vec![1])],
            signals_num: 4,
            components: vec![Some(0), Some(1)], // References to template1 and template2
            body: vec![],
        };

        // Second middle template has one child and one None
        let template6 = ast::Template {
            name: "Middle2".to_string(),
            outputs: vec![Signal::Ff(vec![1])],
            inputs: vec![Signal::Ff(vec![1])],
            signals_num: 4,
            components: vec![Some(2), None, Some(3)], // References to template3, None, and template4
            body: vec![],
        };

        // Create root template with two children
        let template7 = ast::Template {
            name: "Root".to_string(),
            outputs: vec![Signal::Ff(vec![1])],
            inputs: vec![Signal::Ff(vec![1])],
            signals_num: 5,
            components: vec![Some(4), Some(5)], // References to template5 and template6
            body: vec![],
        };

        let templates = vec![template1, template2, template3, template4, template5, template6, template7];

        // Build component tree with template7 (Root) as the main template
        let component_tree = build_component_tree(&templates, 6);

        // Verify the structure of the root component
        assert_eq!(component_tree.signals_start, 1);
        assert_eq!(component_tree.template_id, 6);
        assert_eq!(component_tree.number_of_inputs, 1);
        assert_eq!(component_tree.components.len(), 2);

        // Verify the first child component (Middle1)
        let middle1 = component_tree.components[0].as_ref().unwrap();
        assert_eq!(middle1.signals_start, 6); // 1 (start) + 5 (signals_num of root)
        assert_eq!(middle1.template_id, 4);
        assert_eq!(middle1.number_of_inputs, 1);
        assert_eq!(middle1.components.len(), 2);

        // Verify the second child component (Middle2)
        let middle2 = component_tree.components[1].as_ref().unwrap();
        assert_eq!(middle2.signals_start, 16); // 6 (start of middle1) + 4 (signals_num of middle1) + 3 (signals_num of leaf1) + 3 (signals_num of leaf2)
        assert_eq!(middle2.template_id, 5);
        assert_eq!(middle2.number_of_inputs, 1);
        assert_eq!(middle2.components.len(), 3);

        // Verify Middle2 has a None component
        assert!(middle2.components[1].is_none());

        // Verify the leaf components of Middle1
        let leaf1 = middle1.components[0].as_ref().unwrap();
        assert_eq!(leaf1.signals_start, 10); // 6 (start of middle1) + 4 (signals_num of middle1)
        assert_eq!(leaf1.template_id, 0);
        assert_eq!(leaf1.number_of_inputs, 1);
        assert_eq!(leaf1.components.len(), 0);

        let leaf2 = middle1.components[1].as_ref().unwrap();
        assert_eq!(leaf2.signals_start, 13); // 10 (start of leaf1) + 3 (signals_num of leaf1)
        assert_eq!(leaf2.template_id, 1);
        assert_eq!(leaf2.number_of_inputs, 1);
        assert_eq!(leaf2.components.len(), 0);

        // Verify the leaf components of Middle2
        let leaf3 = middle2.components[0].as_ref().unwrap();
        assert_eq!(leaf3.signals_start, 20); // 16 (start of middle2) + 4 (signals_num of middle2)
        assert_eq!(leaf3.template_id, 2);
        assert_eq!(leaf3.number_of_inputs, 1);
        assert_eq!(leaf3.components.len(), 0);

        let leaf4 = middle2.components[2].as_ref().unwrap();
        assert_eq!(leaf4.signals_start, 23); // 20 (start of leaf3) + 3 (signals_num of leaf3)
        assert_eq!(leaf4.template_id, 3);
        assert_eq!(leaf4.number_of_inputs, 1);
        assert_eq!(leaf4.components.len(), 0);
    }

    #[test]
    fn test_compile_template() {
        let ast_tmpl = ast::Template {
            name: "Multiplier_0".to_string(),
            outputs: vec![],
            inputs: vec![],
            signals_num: 0,
            components: vec![],
            body: vec![
                assign_ff("x_0", &get_signal("1")),
                assign_ff("x_1", &get_signal("2")),
                assign_ff("x_2", &ff_mul("x_0", "x_1")),
                assign_ff("x_3", &ff_add("x_2", "2")),
                set_signal("0", "x_3"),
            ],
        };
        let ff = Field::new(bn254_prime);
        let function_registry = HashMap::new();
        let vm_tmpl = compile_template(&ast_tmpl, &ff, &function_registry).unwrap();

        let want_output = "00000000 [Multiplier_0] PushI64: 1
00000009 [Multiplier_0] LoadSignal
0000000a [Multiplier_0] StoreVariableFf: 0 (x_0)
00000013 [Multiplier_0] PushI64: 2
0000001c [Multiplier_0] LoadSignal
0000001d [Multiplier_0] StoreVariableFf: 1 (x_1)
00000026 [Multiplier_0] LoadVariableFf: 1 (x_1)
0000002f [Multiplier_0] LoadVariableFf: 0 (x_0)
00000038 [Multiplier_0] OpMul
00000039 [Multiplier_0] StoreVariableFf: 2 (x_2)
00000042 [Multiplier_0] PushFf: 2
00000063 [Multiplier_0] LoadVariableFf: 2 (x_2)
0000006c [Multiplier_0] OpAdd
0000006d [Multiplier_0] StoreVariableFf: 3 (x_3)
00000076 [Multiplier_0] LoadVariableFf: 3 (x_3)
0000007f [Multiplier_0] PushI64: 0
00000088 [Multiplier_0] StoreSignal
";

        let actual_output = capture_disassembly("Multiplier_0", &vm_tmpl.code, &vm_tmpl.ff_variable_names, &vm_tmpl.i64_variable_names);

        assert_eq!(actual_output, want_output);

        // disassemble::<U254>(&[vm_tmpl]);
    }

    #[test]
    fn test_compile_branch() {
        let ff = Field::new(bn254_prime);
        let function_registry = HashMap::new();
        let mut ctx = TemplateCompilationContext::new(&function_registry);
        let inst = Statement::Branch {
            condition: Expr::I64(I64Expr::Literal(3)),
            if_block: vec![
                assign_ff("x", &self::ff("5")),
            ],
            else_block: vec![
                assign_ff("x", &self::ff("10")),
            ],
        };
        instruction(&mut ctx, &ff, &inst).unwrap();
        ctx.code.push(OpCode::NoOp as u8);

        let want_output = concat!(
            "00000000 [test      ] PushI64: 3\n",
            "00000009 [test      ] JumpIfFalseI64: +47 -> 0000003d\n",
            "0000000e [test      ] PushFf: 5\n",
            "0000002f [test      ] StoreVariableFf: 0\n",
            "00000038 [test      ] Jump: +42 -> 00000067\n",
            "0000003d [test      ] PushFf: 10\n",
            "0000005e [test      ] StoreVariableFf: 0\n",
            "00000067 [test      ] NoOp\n",
        );

        let ff_variable_names = HashMap::new();
        let i64_variable_names = HashMap::new();
        let actual_output = capture_disassembly(
            "test", &ctx.code, &ff_variable_names, &i64_variable_names);

        assert_eq!(actual_output, want_output);
    }

    fn capture_disassembly(
        name: &str, code: &[u8], ff_variable_names: &HashMap<usize, String>,
        i64_variable_names: &HashMap<usize, String>) -> String {

        let mut actual_output = String::new();
        let mut ip: usize = 0;
        while ip < code.len() {
            let (new_ip, instruction_output) = disassemble_instruction_to_string::<U254>(
                code, ip, name, ff_variable_names, i64_variable_names);
            actual_output.push_str(&instruction_output);
            actual_output.push('\n');
            ip = new_ip;
        }
        actual_output
    }

    #[test]
    fn test_compile_assignment() {
        let ff = Field::new(bn254_prime);
        let function_registry = HashMap::new();
        let mut ctx = TemplateCompilationContext::new(&function_registry);
        
        // Test 1: Variable assignment (FF to FF)
        // First, create a source FF variable
        let inst1 = assign_ff("x_src", &self::ff("42"));
        instruction(&mut ctx, &ff, &inst1).unwrap();
        
        // Now test assignment from variable to variable
        let inst2 = Statement::Assignment {
            name: "x_dest".to_string(),
            value: Expr::Variable("x_src".to_string()),
        };
        instruction(&mut ctx, &ff, &inst2).unwrap();
        
        // Test 2: Variable assignment (I64 to I64)
        let inst3 = assign_i64("i_src", &I64Expr::Literal(100));
        instruction(&mut ctx, &ff, &inst3).unwrap();
        
        let inst4 = Statement::Assignment {
            name: "i_dest".to_string(),
            value: Expr::Variable("i_src".to_string()),
        };
        instruction(&mut ctx, &ff, &inst4).unwrap();
        
        // Test 3: Direct FF expression assignment
        let inst5 = Statement::Assignment {
            name: "x_direct".to_string(),
            value: Expr::Ff(FfExpr::Literal(BigUint::from(99u32))),
        };
        instruction(&mut ctx, &ff, &inst5).unwrap();
        
        // Test 4: Direct I64 expression assignment
        let inst6 = Statement::Assignment {
            name: "i_direct".to_string(),
            value: Expr::I64(I64Expr::Literal(200)),
        };
        instruction(&mut ctx, &ff, &inst6).unwrap();
        
        // Verify that variable types were tracked correctly
        assert!(matches!(ctx.variable_types.get("x_src"), Some(&VariableType::Ff)));
        assert!(matches!(ctx.variable_types.get("x_dest"), Some(&VariableType::Ff)));
        assert!(matches!(ctx.variable_types.get("i_src"), Some(&VariableType::I64)));
        assert!(matches!(ctx.variable_types.get("i_dest"), Some(&VariableType::I64)));
        assert!(matches!(ctx.variable_types.get("x_direct"), Some(&VariableType::Ff)));
        assert!(matches!(ctx.variable_types.get("i_direct"), Some(&VariableType::I64)));
    }

    #[test]
    fn test_parse_signals_json() {
        let ff = Field::new(bn254_prime);

        // bools
        let i = r#"
{
  "a": true,
  "b": false,
  "c": 100500
}"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("a".to_string(), U254::from_str("1").unwrap());
        want.insert("b".to_string(), U254::from_str("0").unwrap());
        want.insert("c".to_string(), U254::from_str("100500").unwrap());
        assert_eq!(want, result);

        // embedded objects
        let i = r#"{ "a": { "b": true } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("a.b".to_string(), U254::from_str("1").unwrap());
        assert_eq!(want, result);

        // null error
        let i = r#"{ "a": { "b": null } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff);
        let binding = result.unwrap_err();
        let err = binding.downcast_ref::<RuntimeError>().unwrap();
        assert!(matches!(err, RuntimeError::InvalidSignalsJson(x) if x == "unexpected null value at path a.b"));

        // Negative number
        let i = r#"{ "a": { "b": -4 } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("a.b".to_string(), U254::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495613").unwrap());
        assert_eq!(want, result);

        // Float number error
        let i = r#"{ "a": { "b": 8.3 } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff);
        let binding = result.unwrap_err();
        let err = binding.downcast_ref::<RuntimeError>().unwrap();
        let msg = err.to_string();
        assert!(matches!(err, RuntimeError::InvalidSignalsJson(x) if x == "invalid number at path a.b: 8.3"), "{}", msg);

        // string
        let i = r#"{ "a": { "b": "8" } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("a.b".to_string(), U254::from_str("8").unwrap());
        assert_eq!(want, result);

        // array
        let i = r#"{ "a": { "b": ["8", 2, 3] } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("a.b[0]".to_string(), U254::from_str("8").unwrap());
        want.insert("a.b[1]".to_string(), U254::from_str("2").unwrap());
        want.insert("a.b[2]".to_string(), U254::from_str("3").unwrap());
        assert_eq!(want, result);

        // buses and arrays
        let i = r#"{
  "a": ["300", 3, "8432", 3, 2],
  "inB": "100500",
  "v": {
    "v": [
      {
        "start": {"x": 3, "y": 5},
        "end": {"x": 6, "y": 7}
      },
      {
        "start": {"x": 8, "y": 9},
        "end": {"x": 10, "y": 11}
      }
    ]
  }
}"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("a[0]".to_string(), U254::from_str("300").unwrap());
        want.insert("a[1]".to_string(), U254::from_str("3").unwrap());
        want.insert("a[2]".to_string(), U254::from_str("8432").unwrap());
        want.insert("a[3]".to_string(), U254::from_str("3").unwrap());
        want.insert("a[4]".to_string(), U254::from_str("2").unwrap());
        want.insert("inB".to_string(), U254::from_str("100500").unwrap());
        want.insert("v.v[0].start.x".to_string(), U254::from_str("3").unwrap());
        want.insert("v.v[0].start.y".to_string(), U254::from_str("5").unwrap());
        want.insert("v.v[0].end.x".to_string(), U254::from_str("6").unwrap());
        want.insert("v.v[0].end.y".to_string(), U254::from_str("7").unwrap());
        want.insert("v.v[1].start.x".to_string(), U254::from_str("8").unwrap());
        want.insert("v.v[1].start.y".to_string(), U254::from_str("9").unwrap());
        want.insert("v.v[1].end.x".to_string(), U254::from_str("10").unwrap());
        want.insert("v.v[1].end.y".to_string(), U254::from_str("11").unwrap());
        assert_eq!(want, result);
    }

    fn assign_ff(var_name: &str, expr: &FfExpr) -> Statement {
        Statement::Assignment {
            name: var_name.to_string(),
            value: Expr::Ff(expr.clone()),
        }
    }

    fn assign_i64(var_name: &str, expr: &I64Expr) -> Statement {
        Statement::Assignment {
            name: var_name.to_string(),
            value: Expr::I64(expr.clone()),
        }
    }

    fn is_alpha_or_underscore(s: &str) -> bool {
        if let Some(c) = s.chars().next() {
            if c.is_alphabetic() || c == '_' {
                return true;
            }
        }
        false
    }

    fn i64_op(n: &str) -> I64Operand {
        let is_var = is_alpha_or_underscore(n);
        if is_var {
            I64Operand::Variable(n.to_string())
        } else {
            I64Operand::Literal(n.parse().unwrap())
        }
    }

    fn get_signal(op1: &str) -> FfExpr {
        FfExpr::GetSignal(i64_op(op1))
    }

    fn set_signal(op1: &str, op2: &str) -> Statement {
        Statement::SetSignal {
            idx: i64_op(op1),
            value: ff(op2),
        }
    }

    fn big_uint(n: &str) -> BigUint {
        BigUint::from_str_radix(n, 10).unwrap()
    }

    fn ff(n: &str) -> FfExpr {
        let is_var = is_alpha_or_underscore(n);

        if is_var {
            FfExpr::Variable(n.to_string())
        } else {
            FfExpr::Literal(big_uint(n))
        }
    }

    fn ff_mul(op1: &str, op2: &str) -> FfExpr {
        FfExpr::FfMul(
            Box::new(ff(op1)),
            Box::new(ff(op2))
        )
    }

    fn ff_add(op1: &str, op2: &str) -> FfExpr {
        FfExpr::FfAdd(
            Box::new(ff(op1)),
            Box::new(ff(op2))
        )
    }

    #[test]
    fn test_build_input_info() {
        // Parse the example CVM file
        let cvm_content = r#";; Prime value
%%prime 21888242871839275222246405745257275088548364400416034343698204186575808495617


;; Memory of signals
%%signals 44


;; Heap of components
%%components_heap 16


;; Types (for each field we store name type offset size nDims dims)
%%type $bus_0
       $x $ff 0 1 0
       $y $ff 1 1 0
%%type $bus_1
       $start $$bus_0 0 2 0
       $end $$bus_0 2 2 0
%%type $bus_2
       $v $$bus_1 0 4 1  2


;; Main template
%%start Main_2


;; Component creation mode (implicit/explicit)
%%components implicit


;; Witness (signal list)
%%witness 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 30 31 32 33 35 36

%%template Tmpl1_0 [ ff 0 ] [ ff 1 2] [3] [ ]
x_0 = i64.0
x_1 = get_signal i64.1

%%template Tmpl2_1 [ ff 0 ] [ ff 1 3] [4] [ ]
x_4 = i64.0
x_5 = get_signal i64.1


%%template Main_2 [ ff 2 2 3 bus_1 0 ] [ ff 1 5 ff 0  bus_2 0 ] [33] [ 0 -1 0 1 ]
x_10 = i64.2
x_11 = get_signal i64.16
"#;

        let sym_content = r#"1,1,2,main.out[0][0]
2,2,2,main.out[0][1]
3,3,2,main.out[0][2]
4,4,2,main.out[1][0]
5,5,2,main.out[1][1]
6,6,2,main.out[1][2]
7,7,2,main.v2.start.x
8,8,2,main.v2.start.y
9,9,2,main.v2.end.x
10,10,2,main.v2.end.y
11,11,2,main.a[0]
12,12,2,main.a[1]
13,13,2,main.a[2]
14,14,2,main.a[3]
15,15,2,main.a[4]
16,16,2,main.inB
17,17,2,main.v.v[0].start.x
18,18,2,main.v.v[0].start.y
19,19,2,main.v.v[0].end.x
20,20,2,main.v.v[0].end.y
21,21,2,main.v.v[1].start.x
22,22,2,main.v.v[1].start.y
23,23,2,main.v.v[1].end.x
24,24,2,main.v.v[1].end.y
25,25,2,main.s
26,26,2,main.s2[0]
27,27,2,main.s2[1]
28,-1,2,main.s2[2]
29,-1,2,main.s2[3]
30,28,2,main.s4[0]
31,29,2,main.s4[1]
32,30,2,main.s4[2]
33,31,2,main.s4[3]
34,-1,1,main.b.out
35,32,1,main.b.in[0]
36,33,1,main.b.in[1]
37,-1,1,main.b.in[2]
38,-1,0,main.c1[0].out
39,-1,0,main.c1[0].in[0]
40,-1,0,main.c1[0].in[1]
41,-1,0,main.c1[2].out
42,-1,0,main.c1[2].in[0]
43,-1,0,main.c1[2].in[1]
"#;

        // Parse the CVM content
        let program = parse(cvm_content).unwrap();

        // Find the main template ID
        let mut main_template_id = None;
        for (i, t) in program.templates.iter().enumerate() {
            if t.name == program.start {
                main_template_id = Some(i);
                break;
            }
        }
        let main_template_id = main_template_id.unwrap();

        // Build input info
        let input_infos = build_input_info_from_sym(
            sym_content,
            main_template_id,
            &program.templates[main_template_id],
            &program.types
        ).unwrap();

        // Verify expected results
        let expected = vec![
            InputInfo {
                name: "a".to_string(),
                offset: 11,
                lengths: vec![5],
                type_id: None,
            },
            InputInfo {
                name: "inB".to_string(),
                offset: 16,
                lengths: vec![],
                type_id: None,
            },
            InputInfo {
                name: "v".to_string(),
                offset: 17,
                lengths: vec![],
                type_id: Some("bus_2".to_string()),
            },
        ];

        assert_eq!(input_infos, expected);
    }

    #[test]
    fn test_build_input_info_with_custom_component_name() {
        // Test with a component name other than "main"
        let sym_content = r#"1,1,2,myComponent.out[0][0]
2,2,2,myComponent.out[0][1]
3,3,2,myComponent.out[0][2]
4,4,2,myComponent.out[1][0]
5,5,2,myComponent.out[1][1]
6,6,2,myComponent.out[1][2]
7,7,2,myComponent.v2.start.x
8,8,2,myComponent.v2.start.y
9,9,2,myComponent.v2.end.x
10,10,2,myComponent.v2.end.y
11,11,2,myComponent.a[0]
12,12,2,myComponent.a[1]
13,13,2,myComponent.a[2]
14,14,2,myComponent.a[3]
15,15,2,myComponent.a[4]
16,16,2,myComponent.inB
17,17,2,myComponent.v.v[0].start.x
18,18,2,myComponent.v.v[0].start.y
19,19,2,myComponent.v.v[0].end.x
20,20,2,myComponent.v.v[0].end.y
21,21,2,myComponent.v.v[1].start.x
22,22,2,myComponent.v.v[1].start.y
23,23,2,myComponent.v.v[1].end.x
24,24,2,myComponent.v.v[1].end.y
25,25,2,myComponent.s
26,26,2,myComponent.s2[0]
27,27,2,myComponent.s2[1]
28,-1,2,myComponent.s2[2]
29,-1,2,myComponent.s2[3]
30,28,2,myComponent.s4[0]
31,29,2,myComponent.s4[1]
32,30,2,myComponent.s4[2]
33,31,2,myComponent.s4[3]
34,-1,1,myComponent.b.out
35,32,1,myComponent.b.in[0]
36,33,1,myComponent.b.in[1]
37,-1,1,myComponent.b.in[2]
38,-1,0,myComponent.c1[0].out
39,-1,0,myComponent.c1[0].in[0]
40,-1,0,myComponent.c1[0].in[1]
41,-1,0,myComponent.c1[2].out
42,-1,0,myComponent.c1[2].in[0]
43,-1,0,myComponent.c1[2].in[1]
"#;

        // Parse the CVM content - same as before
        let cvm_content = r#";; Prime value
%%prime 21888242871839275222246405745257275088548364400416034343698204186575808495617


;; Memory of signals
%%signals 44


;; Heap of components
%%components_heap 16


;; Types (for each field we store name type offset size nDims dims)
%%type $bus_0
       $x $ff 0 1 0
       $y $ff 1 1 0
%%type $bus_1
       $start $$bus_0 0 2 0
       $end $$bus_0 2 2 0
%%type $bus_2
       $v $$bus_1 0 4 1  2


;; Main template
%%start Main_2


;; Component creation mode (implicit/explicit)
%%components implicit


;; Witness (signal list)
%%witness 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 30 31 32 33 35 36

%%template Tmpl1_0 [ ff 0 ] [ ff 1 2] [3] [ ]
x_0 = i64.0
x_1 = get_signal i64.1

%%template Tmpl2_1 [ ff 0 ] [ ff 1 3] [4] [ ]
x_4 = i64.0
x_5 = get_signal i64.1


%%template Main_2 [ ff 2 2 3 bus_1 0 ] [ ff 1 5 ff 0  bus_2 0 ] [33] [ 0 -1 0 1 ]
x_10 = i64.2
x_11 = get_signal i64.16
"#;

        let program = parse(cvm_content).unwrap();

        // Find the main template ID
        let mut main_template_id = None;
        for (i, t) in program.templates.iter().enumerate() {
            if t.name == program.start {
                main_template_id = Some(i);
                break;
            }
        }
        let main_template_id = main_template_id.unwrap();

        // Build input info with custom component name
        let input_infos = build_input_info_from_sym(
            sym_content,
            main_template_id,
            &program.templates[main_template_id],
            &program.types
        ).unwrap();

        // Should still get the same results - just the component name prefix changes
        let expected = vec![
            InputInfo {
                name: "a".to_string(),
                offset: 11,
                lengths: vec![5],
                type_id: None,
            },
            InputInfo {
                name: "inB".to_string(),
                offset: 16,
                lengths: vec![],
                type_id: None,
            },
            InputInfo {
                name: "v".to_string(),
                offset: 17,
                lengths: vec![],
                type_id: Some("bus_2".to_string()),
            },
        ];

        assert_eq!(input_infos, expected);
    }

    #[test]
    fn test_array_detection() {
        // Test that we correctly reject invalid array indices (not [0])
        let sym_content = r#"1,1,0,main.out[0]
2,2,0,main.out[1]
3,3,0,main.arrayInput[0]
4,4,0,main.arrayInput[1]
5,5,0,main.arrayInput[2]
6,6,0,main.nonArrayInput
7,7,0,main.busArray[0].x
8,8,0,main.busArray[0].y
9,9,0,main.busArray[1].x
10,10,0,main.busArray[1].y
11,11,0,main.notArray[5]
12,12,0,main.regularBus.x
13,13,0,main.regularBus.y
"#;

        let cvm_content = r#";; Prime value
%%prime 21888242871839275222246405745257275088548364400416034343698204186575808495617

;; Memory of signals
%%signals 14

;; Heap of components
%%components_heap 1

;; Types (for each field we store name type offset size nDims dims)
%%type $bus_0
       $x $ff 0 1 0
       $y $ff 1 1 0

;; Main template
%%start Main_0

;; Component creation mode (implicit/explicit)
%%components implicit

;; Witness (signal list)
%%witness 0 1 2 3 4 5 6 7 8 9 10 11 12 13

%%template Main_0 [ ff 1 2 ] [ ff 1 3 ff 0 bus_0 1 2 ff 0 bus_0 0 ] [14] [ ]
x_0 = get_signal i64.1
"#;

        let program = parse(cvm_content).unwrap();
        let main_template_id = program.templates.iter().position(|t| t.name == program.start).unwrap();

        // This should fail because main.notArray[5] has invalid array index [5] instead of [0]
        let result = build_input_info_from_sym(
            sym_content,
            main_template_id,
            &program.templates[main_template_id],
            &program.types
        );

        assert!(result.is_err());
        if let Err(e) = result {
            let error_message = e.to_string();
            assert!(error_message.contains("Invalid array index in signal name 'notArray[5]': expected [0] but found '[5]'"));
        }
    }

    #[test]
    fn test_missing_signal_error() {
        // Test that we get an error when a signal is missing from the sym file
        let sym_content = r#"1,1,0,main.out[0]
2,2,0,main.out[1]
3,3,0,main.arrayInput[0]
4,4,0,main.arrayInput[1]
5,5,0,main.arrayInput[2]
6,6,0,main.nonArrayInput
7,7,0,main.busArray[0].x
8,8,0,main.busArray[0].y
9,9,0,main.busArray[1].x
10,10,0,main.busArray[1].y
12,12,0,main.regularBus.x
13,13,0,main.regularBus.y
"#;

        let cvm_content = r#";; Prime value
%%prime 21888242871839275222246405745257275088548364400416034343698204186575808495617

;; Memory of signals
%%signals 15

;; Heap of components
%%components_heap 1

;; Types (for each field we store name type offset size nDims dims)
%%type $bus_0
       $x $ff 0 1 0
       $y $ff 1 1 0

;; Main template
%%start Main_0

;; Component creation mode (implicit/explicit)
%%components implicit

;; Witness (signal list)
%%witness 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14

%%template Main_0 [ ff 1 2 ] [ ff 1 3 ff 0 bus_0 1 2 ff 0 bus_0 0 ff 0 ] [15] [ ]
x_0 = get_signal i64.1
"#;

        let program = parse(cvm_content).unwrap();
        let main_template_id = program.templates.iter().position(|t| t.name == program.start).unwrap();

        // This should fail because we're missing signal at index 14 (the last ff 0 input)
        let result = build_input_info_from_sym(
            sym_content,
            main_template_id,
            &program.templates[main_template_id],
            &program.types
        );

        assert!(result.is_err());
        if let Err(e) = result {
            let error_message = e.to_string();
            assert!(error_message.contains("Signal at index 11 not found in sym file"));
        }
    }

    #[test]
    fn test_signal_prefix_mismatch_error() {
        // Test that we get an error when a signal doesn't have the expected component prefix
        let sym_content = r#"1,1,0,main.out[0]
2,2,0,main.out[1]
3,3,0,wrongComponent.arrayInput[0]
"#;

        let cvm_content = r#";; Prime value
%%prime 21888242871839275222246405745257275088548364400416034343698204186575808495617

;; Memory of signals
%%signals 4

;; Heap of components
%%components_heap 1

;; Types (for each field we store name type offset size nDims dims)

;; Main template
%%start Main_0

;; Component creation mode (implicit/explicit)
%%components implicit

;; Witness (signal list)
%%witness 0 1 2 3

%%template Main_0 [ ff 1 2 ] [ ff 1 1 ] [4] [ ]
x_0 = get_signal i64.1
"#;

        let program = parse(cvm_content).unwrap();
        let main_template_id = program.templates.iter().position(|t| t.name == program.start).unwrap();

        // This should fail because signal at index 3 has prefix "wrongComponent" instead of "main"
        let result = build_input_info_from_sym(
            sym_content,
            main_template_id,
            &program.templates[main_template_id],
            &program.types
        );

        assert!(result.is_err());
        if let Err(e) = result {
            let error_message = e.to_string();
            assert!(error_message.contains("Signal 'wrongComponent.arrayInput[0]' does not start with expected component prefix 'main.'"));
        }
    }

    #[test]
    fn test_init_signals() {
        // Parse the CVM file to get types and template information
        let cvm_content = include_str!("../../tests/cvm-compile/data/test_init_signals__cvm.txt");
        let sym_content = include_str!("../../tests/cvm-compile/data/test_init_signals__sym.txt");

        let program = parse(cvm_content).unwrap();

        // Find the main template ID
        let main_template_id = program.templates.iter()
            .position(|t| t.name == program.start)
            .unwrap();

        let field = Field::new(bn254_prime);

        let inputs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/cvm-compile/data/test_init_signals__inputs.json");

        let input_infos = build_input_info_from_sym(
            sym_content, main_template_id,
            &program.templates[main_template_id],
            &program.types).unwrap();

        // Call init_signals with the new signature
        let result = init_signals::<U254, _>(
            inputs_path.to_string_lossy().as_ref(),
            44, // signals_num
            &field,
            &program.types,
            &input_infos,
        ).unwrap();

        // Expected result
        let want: Vec<Option<U254>> = vec![
            Some(U254::one()), // 0
            None, // 1
            None, // 2
            None, // 3
            None, // 4
            None, // 5
            None, // 6
            None, // 7
            None, // 8
            None, // 9
            None, // 10
            Some(U254::from_str("1").unwrap()), // 11
            Some(U254::from_str("2").unwrap()), // 12
            Some(U254::from_str("3").unwrap()), // 13
            Some(U254::from_str("4").unwrap()), // 14
            Some(U254::from_str("5").unwrap()), // 15
            Some(U254::from_str("6").unwrap()), // 16
            Some(U254::from_str("7").unwrap()), // 17
            Some(U254::from_str("8").unwrap()), // 18
            Some(U254::from_str("9").unwrap()), // 19
            Some(U254::from_str("10").unwrap()), // 20
            Some(U254::from_str("11").unwrap()), // 21
            Some(U254::from_str("12").unwrap()), // 22
            Some(U254::from_str("13").unwrap()), // 23
            Some(U254::from_str("14").unwrap()), // 24
            None, // 25
            None, // 26
            None, // 27
            None, // 28
            None, // 29
            None, // 30
            None, // 31
            None, // 32
            None, // 33
            None, // 34
            None, // 35
            None, // 36
            None, // 37
            None, // 38
            None, // 39
            None, // 40
            None, // 41
            None, // 42
            None, // 43
        ];

        assert_eq!(result, want);
    }

    #[test]
    fn test_array_inputs() {
        // Parse the CVM file to get types and template information
        let cvm_content = include_str!("../../tests/cvm-compile/data/test_array_inputs__cvm.txt");
        let sym_content = include_str!("../../tests/cvm-compile/data/test_array_inputs__sym.txt");

        let program = parse(cvm_content).unwrap();

        // Find the main template ID
        let main_template_id = program.templates.iter()
            .position(|t| t.name == program.start)
            .unwrap();

        let field = Field::new(bn254_prime);

        let inputs_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/cvm-compile/data/test_array_inputs__inputs.json");

        let input_infos = build_input_info_from_sym(
            sym_content, main_template_id,
            &program.templates[main_template_id],
            &program.types).unwrap();

        // Call init_signals with the new signature
        let result = init_signals::<U254, _>(
            inputs_path.to_string_lossy().as_ref(),
            19, // signals_num
            &field,
            &program.types,
            &input_infos,
        ).unwrap();

        // Expected result
        let want: Vec<Option<U254>> = vec![
            Some(U254::one()), // 0
            None, // 1
            None, // 2
            None, // 3
            None, // 4
            None, // 5
            None, // 6
            Some(U254::from_str("1").unwrap()), // 7
            Some(U254::from_str("2").unwrap()), // 8
            Some(U254::from_str("3").unwrap()), // 9
            Some(U254::from_str("4").unwrap()), // 10
            Some(U254::from_str("5").unwrap()), // 11
            Some(U254::from_str("6").unwrap()), // 12
            Some(U254::from_str("7").unwrap()), // 13
            Some(U254::from_str("8").unwrap()), // 14
            Some(U254::from_str("9").unwrap()), // 15
            Some(U254::from_str("10").unwrap()), // 16
            Some(U254::from_str("11").unwrap()), // 17
            Some(U254::from_str("12").unwrap()), // 18
        ];

        assert_eq!(result, want);
    }
}
