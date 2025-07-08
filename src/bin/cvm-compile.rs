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
    LoopControlJumpsEmpty
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
            calculate_witness(
                &circuit, &mut component_tree, args.want_wtns.unwrap())
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
    want_wtns: WantWtns) -> Result<(), Box<dyn Error>> {

    let mut signals = init_signals(
        &want_wtns.inputs_file, circuit.signals_num, &circuit.field,
        &circuit.input_signals_info)?;
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
    visit_inputs_json("main", &v, &mut records, ff)?;
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
            records.insert(prefix.to_string(), v);
        },
        serde_json::Value::String(s) => {
            records.insert(prefix.to_string(), ff.parse_str(s)?);
        },
        serde_json::Value::Array(vs) => {
            for (i, v) in vs.iter().enumerate() {
                let new_prefix = format!("{}[{}]", prefix, i);
                visit_inputs_json(&new_prefix, v, records, ff)?;
            }
        },
        serde_json::Value::Object(o) => {
            for (k, v) in o.iter() {
                let new_prefix = prefix.to_string() + "." + k;
                visit_inputs_json(&new_prefix, v, records, ff)?;
            }
        },
    };

    Ok(())
}

fn init_signals<T: FieldOps, F>(
    inputs_file: &str, signals_num: usize, ff: &F,
    input_signals_info: &HashMap<String, usize>) -> Result<Vec<Option<T>>, Box<dyn Error>>
where
    for <'a> &'a F: FieldOperations<Type = T> {

    let mut signals = vec![None; signals_num];
    signals[0] = Some(T::one());

    let inputs_data = fs::read_to_string(inputs_file)?;
    let input_signals = parse_signals_json(inputs_data.as_bytes(), ff)?;
    for (path, value) in input_signals.iter() {
        match input_signals_info.get(path) {
            None => {
                if path.ends_with("[0]") {
                    let path = path.trim_end_matches("[0]");
                    if let Some(signal_idx) = input_signals_info.get(path) {
                        signals[*signal_idx] = Some(*value);
                        continue;
                    }
                }
                return Err(Box::new(
                    RuntimeError::InvalidSignalsJson(
                        format!("signal {} is not found in SYM file", path))))
            },
            Some(signal_idx) => signals[*signal_idx] = Some(*value),
        }
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
        want.insert("main.a".to_string(), U254::from_str("1").unwrap());
        want.insert("main.b".to_string(), U254::from_str("0").unwrap());
        want.insert("main.c".to_string(), U254::from_str("100500").unwrap());
        assert_eq!(want, result);

        // embedded objects
        let i = r#"{ "a": { "b": true } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("main.a.b".to_string(), U254::from_str("1").unwrap());
        assert_eq!(want, result);

        // null error
        let i = r#"{ "a": { "b": null } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff);
        let binding = result.unwrap_err();
        let err = binding.downcast_ref::<RuntimeError>().unwrap();
        assert!(matches!(err, RuntimeError::InvalidSignalsJson(x) if x == "unexpected null value at path main.a.b"));

        // Negative number
        let i = r#"{ "a": { "b": -4 } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("main.a.b".to_string(), U254::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495613").unwrap());
        assert_eq!(want, result);

        // Float number error
        let i = r#"{ "a": { "b": 8.3 } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff);
        let binding = result.unwrap_err();
        let err = binding.downcast_ref::<RuntimeError>().unwrap();
        let msg = err.to_string();
        assert!(matches!(err, RuntimeError::InvalidSignalsJson(x) if x == "invalid number at path main.a.b: 8.3"), "{}", msg);

        // string
        let i = r#"{ "a": { "b": "8" } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("main.a.b".to_string(), U254::from_str("8").unwrap());
        assert_eq!(want, result);

        // array
        let i = r#"{ "a": { "b": ["8", 2, 3] } }"#;
        let result = parse_signals_json(i.as_bytes(), &ff).unwrap();
        let mut want: HashMap<String, U254> = HashMap::new();
        want.insert("main.a.b[0]".to_string(), U254::from_str("8").unwrap());
        want.insert("main.a.b[1]".to_string(), U254::from_str("2").unwrap());
        want.insert("main.a.b[2]".to_string(), U254::from_str("3").unwrap());
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
        want.insert("main.a[0]".to_string(), U254::from_str("300").unwrap());
        want.insert("main.a[1]".to_string(), U254::from_str("3").unwrap());
        want.insert("main.a[2]".to_string(), U254::from_str("8432").unwrap());
        want.insert("main.a[3]".to_string(), U254::from_str("3").unwrap());
        want.insert("main.a[4]".to_string(), U254::from_str("2").unwrap());
        want.insert("main.inB".to_string(), U254::from_str("100500").unwrap());
        want.insert("main.v.v[0].start.x".to_string(), U254::from_str("3").unwrap());
        want.insert("main.v.v[0].start.y".to_string(), U254::from_str("5").unwrap());
        want.insert("main.v.v[0].end.x".to_string(), U254::from_str("6").unwrap());
        want.insert("main.v.v[0].end.y".to_string(), U254::from_str("7").unwrap());
        want.insert("main.v.v[1].start.x".to_string(), U254::from_str("8").unwrap());
        want.insert("main.v.v[1].start.y".to_string(), U254::from_str("9").unwrap());
        want.insert("main.v.v[1].end.x".to_string(), U254::from_str("10").unwrap());
        want.insert("main.v.v[1].end.y".to_string(), U254::from_str("11").unwrap());
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
}
