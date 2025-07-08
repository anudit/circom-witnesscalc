// AST definitions for Circom assembly language
// Refined with full instruction set from circom-virtual-machine.md

use num_bigint::BigUint;

// /// Top-level AST node
// #[derive(Debug)]
// pub enum AstNode {
//     Directive(Directive),
//     Template(Template),
// }
//
// /// Assembly directives (lines starting with `%%`)
// #[derive(Debug)]
// pub enum Directive {
//     Prime(BigUint),                       // %%prime
//     Signals(usize),                       // %%signals
//     ComponentsHeap(usize),                // %%components_heap
//     Start(String),                        // %%start
//     ComponentsMode(ComponentsMode),       // %%components
//     Witness(Vec<usize>),                  // %%witness
//     Types(Vec<TypeDef>),                  // %%types definitions
// }
//
// /// Component creation mode
// #[derive(Debug)]
// pub enum ComponentsMode {
//     Implicit,
//     Explicit,
// }
//
// /// Optional type definitions for fields/signals
// #[derive(Debug)]
// pub struct TypeDef {
//     pub name: String,
//     pub ty: String,
//     pub offset: usize,
//     pub size: usize,
//     pub dims: Vec<usize>,
// }
//  
// /// A template (`%%template` block)
// #[derive(Debug)]
// pub struct Template {
//     pub name: String,                    // Template name
//     pub ff_inputs: Vec<Literal>,         // Constants/refs, e.g. ff./i64.
//     pub ff_outputs: Vec<Literal>,
//     pub signals: Vec<Literal>,           // signal counts
//     pub extra: Vec<String>,              // extra metadata or dims
//     pub body: Vec<Instruction>,          // Sequence of instructions
// }
//
// /// Individual instructions
// #[derive(Debug)]
// pub enum Instruction {
//     // Arithmetic operations
//     /// i64.add, i64.sub, i64.mul, i64.div, i64.rem
//     I64Op { op: I64Op, args: Vec<Expr>, dest: String },
//     /// ff.add, ff.sub, ff.mul, ff.idiv, ff.div, ff.rem, ff.pow, 64.pow
//     FfOp  { op: FfOp,  args: Vec<Expr>, dest: String },
//
//     // Relational operations
//     I64RelOp{ op: I64RelOp, args: Vec<Expr>, dest: String },
//     FfRelOp { op: FfRelOp,  args: Vec<Expr>, dest: String },
//
//     // Boolean operations
//     I64BoolOp{ op: I64BoolOp, args: Vec<Expr>, dest: String },
//     FfBoolOp { op: FfBoolOp,  args: Vec<Expr>, dest: String },
//
//     // Bit operations
//     I64BitOp { op: I64BitOp, args: Vec<Expr>, dest: String },
//     FfBitOp  { op: FfBitOp,  args: Vec<Expr>, dest: String },
//
//     // Conversions: extend_ff, wrap_i64
//     Convert  { op: ConvertOp, arg: Box<Expr>, dest: String },
//
//     // Memory operations
//     I64Load  { dest: String, addr: Box<Expr> },             // i64.load
//     FfLoad   { dest: String, addr: Box<Expr> },             // ff.load
//     I64Store { addr: Box<Expr>, value: Box<Expr> },         // i64.store
//     FfStore  { addr: Box<Expr>, value: Box<Expr> },         // ff.store
//     FfMstore { dest_addr: Box<Expr>, src_addr: Box<Expr>, size: Box<Expr> },
//     FfMstoreFromSignal    { dest_addr: Box<Expr>, signal_idx: Box<Expr>, size: Box<Expr> },
//     FfMstoreFromCmpSignal { dest_addr: Box<Expr>, cmp_idx: Box<Expr>, signal_idx: Box<Expr>, size: Box<Expr> },
//
//     // Signal memory operations
//     GetSignal                { dest: String, idx: Expr },
//     GetCmpSignal             { dest: String, cmp: Expr, idx: Expr },
//     SetSignal                { idx: Expr, value: Expr },
//     MsetSignal               { dest: Expr, src: Expr, size: Expr },
//     MsetSignalFromMemory     { dest: Expr, addr: Expr, size: Expr },
//     SetCmpInput              { cmp: Expr, idx: Expr, value: Expr },
//     MsetCmpInput             { cmp: Expr, dest: Expr, src: Expr, size: Expr },
//     MsetCmpInputCnt          { cmp: Expr, dest: Expr, src: Expr, size: Expr },
//     MsetCmpInputRun          { cmp: Expr, dest: Expr, src: Expr, size: Expr },
//     MsetCmpInputCntCheck     { cmp: Expr, dest: Expr, src: Expr, size: Expr },
//     MsetCmpInputFromCmp      { cmp1: Expr, sidx1: Expr, cmp2: Expr, sidx2: Expr, size: Expr },
//     MsetCmpInputFromCmpCnt   { cmp1: Expr, sidx1: Expr, cmp2: Expr, sidx2: Expr, size: Expr },
//     MsetCmpInputFromCmpRun   { cmp1: Expr, sidx1: Expr, cmp2: Expr, sidx2: Expr, size: Expr },
//     MsetCmpInputFromCmpCntCheck { cmp1: Expr, sidx1: Expr, cmp2: Expr, sidx2: Expr, size: Expr },
//     MsetCmpInputFromMemory   { cmp: Expr, sidx: Expr, addr: Expr, size: Expr },
//     MsetCmpInputFromMemoryCnt { cmp: Expr, sidx: Expr, addr: Expr, size: Expr },
//     MsetCmpInputFromMemoryRun { cmp: Expr, sidx: Expr, addr: Expr, size: Expr },
//     MsetCmpInputFromMemoryCntCheck { cmp: Expr, sidx: Expr, addr: Expr, size: Expr },
//
//     // Control flow
//     Loop    { body: Vec<Instruction> },
//     Break,
//     Continue,
//     If      { cond: Expr, then_branch: Vec<Instruction>, else_branch: Option<Vec<Instruction>> },
//
//     // Function calls and returns
//     Call       { kind: CallKind, name: String, params: Vec<CallParam>, dest: Option<String> },
//     Return     { op: ReturnOp, value: Vec<Expr> },
//
//     // Template/bus introspection
//     GetTemplateId            { dest: String, subcmp: Expr },
//     GetTemplateSignalPos     { dest: String, tmpl: Expr, sig: Expr },
//     GetTemplateSignalSize    { dest: String, tmpl: Expr, sig: Expr },
//     GetTemplateSignalDim     { dest: String, tmpl: Expr, sig: Expr },
//     GetTemplateSignalType    { dest: String, tmpl: Expr, sig: Expr },
//     GetBusSignalPos          { dest: String, bus: Expr, sig: Expr },
//     GetBusSignalSize         { dest: String, bus: Expr, sig: Expr },
//     GetBusSignalDim          { dest: String, bus: Expr, sig: Expr },
//     GetBusSignalType         { dest: String, bus: Expr, sig: Expr },
//
//     // Misc
//     Other(String),
// }
//
// /// Expressions: signals, literals, or binary operations
// #[derive(Debug)]
// pub enum Expr {
//     Signal(usize),
//     Literal(Literal),
//     BinaryOp { op: BinaryOp, left: Box<Expr>, right: Box<Expr> },
// }

/// Typed literal constants
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Literal {
    I64(i64),    // i64.<value>
    Ff(BigUint), // ff.<value>
}

// /// Integer arithmetic ops
// #[derive(Debug)]
// pub enum I64Op { Add, Sub, Mul, Div, Rem }
//
// /// Field arithmetic ops
// #[derive(Debug)]
// pub enum FfOp  { Add, Sub, Mul, IDiv, Div, Rem, Pow }
//
// /// Integer relational ops
// #[derive(Debug)]
// pub enum I64RelOp { Gt, Ge, Lt, Le, Eq, Neq, Eqz }
//
// /// Field relational ops
// #[derive(Debug)]
// pub enum FfRelOp  { Gt, Ge, Lt, Le, Eq, Neq, Eqz }
//
// /// Integer boolean ops
// #[derive(Debug)]
// pub enum I64BoolOp { And, Or }
//
// /// Field boolean ops
// #[derive(Debug)]
// pub enum FfBoolOp  { And, Or }
//
// /// Integer bitwise ops
// #[derive(Debug)]
// pub enum I64BitOp { Shr, Shl, Band, Bor, Bxor, Bnot }
//
// /// Field bitwise ops
// #[derive(Debug)]
// pub enum FfBitOp  { Shr, Shl, Band, Bor, Bxor, Bnot }
//
// /// Conversions
// #[derive(Debug)]
// pub enum ConvertOp { ExtendFf, WrapI64 }
//
// /// Binary operators
// #[derive(Debug)]
// pub enum BinaryOp { Add, Sub, Mul, Rem, Eq, Neq, Lt }
//
// /// Call kinds
// #[derive(Debug)]
// pub enum CallKind { I64, Ff, Void }
//
// /// Call parameter types
// #[derive(Debug)]
// pub enum CallParam {
//     Expr(Expr),
//     Signal { idx: Expr, size: Expr },
//     CmpSignal { cmp: Expr, idx: Expr, size: Expr },
//     I64Mem { addr: Expr, size: Expr },
//     FfMem { addr: Expr, size: Expr },
// }
//
// /// Return operation types
// #[derive(Debug)]
// pub enum ReturnOp { I64Return, FfReturn, Return }

#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct Template {
    pub name: String,
    pub outputs: Vec<Signal>,
    pub inputs: Vec<Signal>,
    pub signals_num: usize,
    pub components: Vec<Option<usize>>,
    pub body: Vec<Statement>,
}

#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct Function {
    pub name: String,
    pub body: Vec<Statement>,
}

#[cfg_attr(test, derive(PartialEq, Debug))]
pub enum CallArgument {
    Variable(String),
    I64Literal(i64),
    FfLiteral(BigUint),
    I64Memory { addr: I64Operand, size: I64Operand },
    FfMemory { addr: I64Operand, size: I64Operand },
}

#[cfg_attr(test, derive(PartialEq, Debug))]
pub enum Statement {
    Assignment {
        name: String,
        value: Expr,
    },
    SetSignal { idx: I64Operand, value: FfExpr },
    FfStore { idx: I64Operand, value: FfExpr },
    SetCmpSignalRun {
        cmp_idx: I64Operand,
        sig_idx: I64Operand,
        value: FfExpr
    },
    SetCmpInput {
        cmp_idx: I64Expr,
        sig_idx: I64Expr,
        value: FfExpr
    },
    Error { code: I64Operand },
    Branch {
        condition: Expr,
        if_block: Vec<Statement>,
        else_block: Vec<Statement>
    },
    Loop(Vec<Statement>),
    Break,
    Continue,
    FfMReturn { dst: I64Operand, src: I64Operand, size: I64Operand },
    FfMCall {
        name: String,
        args: Vec<CallArgument>,
    }
}

// Clone is always derived (not just in tests) to allow usage across crate boundaries.
// When types are used by binary crates (like cvm-compile), the library is compiled
// without test configuration, so conditional derives wouldn't be available.
#[cfg_attr(test, derive(PartialEq, Debug))]
#[derive(Clone)]
pub enum I64Operand {
    Variable(String),
    Literal(i64),
}

pub enum UnoOp {
    GetSignal,
    // Neg,
    // Id, // identity - just return self
    // Lnot,
    // Bnot,
}

#[cfg_attr(test, derive(PartialEq, Debug))]
pub enum Expr {
    Ff(FfExpr),
    I64(I64Expr),
    Variable(String),
}

// See I64Operand comment above for why Clone is always derived
#[cfg_attr(test, derive(PartialEq, Debug))]
#[derive(Clone)]
pub enum FfExpr {
    GetSignal(I64Operand),
    GetCmpSignal{ cmp_idx: I64Operand, sig_idx: I64Operand },
    FfAdd(Box<FfExpr>, Box<FfExpr>),
    FfMul(Box<FfExpr>, Box<FfExpr>),
    FfNeq(Box<FfExpr>, Box<FfExpr>),
    FfDiv(Box<FfExpr>, Box<FfExpr>),
    FfSub(Box<FfExpr>, Box<FfExpr>),
    FfEq(Box<FfExpr>, Box<FfExpr>),
    FfEqz(Box<FfExpr>),
    FfShr(Box<FfExpr>, Box<FfExpr>),
    FfBand(Box<FfExpr>, Box<FfExpr>),
    Lt(Box<FfExpr>, Box<FfExpr>),
    Variable(String),
    Literal(BigUint),
    Load(I64Operand),
}

// See I64Operand comment above for why Clone is always derived
#[cfg_attr(test, derive(PartialEq, Debug))]
#[derive(Clone)]
pub enum I64Expr {
    Variable(String),
    Literal(i64),
    Add(Box<I64Expr>, Box<I64Expr>),
    Sub(Box<I64Expr>, Box<I64Expr>),
    Mul(Box<I64Expr>, Box<I64Expr>),
    Load(I64Operand),
    Wrap(Box<FfExpr>),
    Lte(Box<I64Expr>, Box<I64Expr>),
}

#[cfg_attr(test, derive(PartialEq, Debug))]
pub enum Signal {
    Ff(Vec<usize>),          // dimensions
    Bus(String, Vec<usize>), // bus name and dimensions
}

#[cfg_attr(test, derive(PartialEq, Debug))]
pub enum ComponentsMode {
    Implicit,
    Explicit,
}

#[cfg_attr(test, derive(PartialEq, Debug))]
pub struct AST {
    pub prime: BigUint,
    pub signals: usize,
    pub components_heap: usize,
    pub start: String,
    pub components_mode: ComponentsMode,
    pub witness: Vec<usize>,
    pub functions: Vec<Function>,
    pub templates: Vec<Template>,
}
