//witnesscalc:enabled !graph_v1 !vm
pragma circom 2.0.0;

bus Point() {
    signal x[2];
    signal y;
}

bus Vector() {
    Point start[2];
    Point end;
}

template Main() {
    signal input a[2][3];
    signal input b[3][2];
    Vector input c;
    Vector input d[2];
    signal output e[6];

    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 3; j++) {
            e[i * 3 + j] <== a[i][j] * b[j][i];
        }
    }
}

component main = Main();