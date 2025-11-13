//witnesscalc:enabled !graph !vm
pragma circom  2.1.6;

bus Point() {
    signal x;
    signal y;
}

bus Vector() {
    Point start;
    Point end;
}

bus TwoVectors() {
    Vector v[2];
}

template Tmpl1() {
    signal input in[2];
    signal output out;
    out <== in[0] * in[1];
}

template Tmpl2() {
    signal input in[3];
    signal output out;
    out <== in[0] * in[1] + in[2];
}

template Main() {
    signal input a[5];
    signal input inB;
    TwoVectors input v;
    signal output out[2][3];
    Vector output v2;
    signal s;
    signal s2[4];
    signal s4[4];

    s4[0] <== v.v[0].start.x * v.v[0].start.y;
    s4[1] <== v.v[0].end.x * v.v[0].end.y;
    s4[2] <== v.v[1].start.x * v.v[1].start.y;
    s4[3] <== v.v[1].end.x * v.v[1].end.y;

    s2[0] <== s4[0] * s4[1];
    s2[1] <== s4[2] * s4[3];

    s <== s2[0] * s2[1];

    component c1[3];
    for (var i = 0; i < 3; i++) {
        if (i != 1) {
            var idx = i == 0 ? 0 : (i - 1) * 2;
            c1[i] = Tmpl1();
            c1[i].in[0] <== a[idx%3];
            c1[i].in[1] <== a[idx%3+1];
        }
    }
    // c1[0] = Tmpl1();
    // c1[0].in[0] <== a[0];
    // c1[0].in[1] <== a[1];
    // c1[2] = Tmpl1();
    // c1[2].in[0] <== a[2];
    // c1[2].in[1] <== a[3];

    component b = Tmpl2();
    b.in[0] <== c1[0].out;
    b.in[1] <== c1[2].out;
    b.in[2] <== a[4];

    out[0][0] <== v.v[0].start.x * v.v[0].start.y;
    out[0][1] <== v.v[0].end.x * v.v[0].end.y;
    out[0][2] <== v.v[1].start.x * v.v[1].start.y;
    out[1][0] <== v.v[1].end.x * v.v[1].end.y;
    out[1][1] <== b.out;
    out[1][2] <== s * b.out + inB;
    // out <== s * b.out + inB;

    v2 <== v.v[0];
}

component main = Main();
