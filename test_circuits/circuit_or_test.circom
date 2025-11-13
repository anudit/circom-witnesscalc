pragma circom 2.0.0;

template OrTest() {
    signal input a;
    signal input b;
    signal output out;
    
    // Test logical OR operation
    // out should be 1 if either a or b is non-zero
    out <-- (a != 0) || (b != 0) ? 1 : 0;
}

component main = OrTest();