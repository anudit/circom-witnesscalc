pragma circom 2.1.9;

template BnotSimple() {
    signal input a;
    signal output out;
    
    // Test bitwise NOT operation
    out <-- ~a;
    
    // Add a constraint to avoid optimization
    signal dummy;
    dummy <-- 0;
    0 === dummy * (out - a);
}

component main = BnotSimple();