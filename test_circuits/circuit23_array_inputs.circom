pragma circom 2.0.0;

template Main() {
    signal input a[2][3];
    signal input b[3][2];
    signal output c[6];

    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 3; j++) {
            c[i * 3 + j] <== a[i][j] * b[j][i];
        }
    }
}

component main = Main();