pragma circom  2.1.6;

function fnc1(x, y) {
    if (y == 0) {
        return x + 1;
    } else {
        return x / y;
    }
}

template Main() {
    signal input a[2];
    signal output b;

    b <== a[0] * a[1] + fnc1(a[0], 5);
}

component main = Main();
