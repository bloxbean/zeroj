pragma circom 2.0.0;

// Multiplier with 2 public signals: a (public input) + c (public output)
// Private input: b
// Constraint: a * b = c
template Multiplier2Pub() {
    signal input a;   // public (declared in main)
    signal input b;   // private
    signal output c;  // public (output)
    c <== a * b;
}

component main {public [a]} = Multiplier2Pub();
