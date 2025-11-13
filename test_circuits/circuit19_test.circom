//witnesscalc:enabled !graph
pragma circom  2.1.6;

template Main() {
    signal input a;
    signal input b;
    signal output out;
    signal dummy;

    var j = 1;
    for (var i = 0; i < b; i++) {
        j = j + 1;
    }

    log(j);

    dummy <-- a * b + j;
    out <== dummy * 3 * b;
}

component main = Main();
