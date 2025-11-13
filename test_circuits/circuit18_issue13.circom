//witnesscalc:enabled !graph
pragma circom  2.1.6;

include "eddsa.circom";

template EdDSADocumentVerifier(MSG_LENGTH) {
    signal input msg[MSG_LENGTH];
    signal input PUB_KEY[256];

    signal input R8[256];
    signal input S[256];

    signal output out;

    component edDSAVerifier = EdDSAVerifier(MSG_LENGTH);

    edDSAVerifier.A <== PUB_KEY;
    edDSAVerifier.msg <== msg;
    edDSAVerifier.R8 <== R8;
    edDSAVerifier.S <== S;

    out <== 1;
}

component main {public [PUB_KEY]} = EdDSADocumentVerifier(744);
