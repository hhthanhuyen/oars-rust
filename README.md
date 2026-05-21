# OARS

This project implements the DDH-based OARS prototype over the Ristretto255 group. Range proofs use dalek Bulletproofs.

## Run

```bash
taskset -c 0 cargo run --release
```

By default, the benchmark uses 100 iterations. To override it:

```bash
OARS_ITER=10 taskset -c 0 cargo run --release
```

## Parameters

The benchmark parameter set is defined in `src/bench.rs`:

```text
(n, k, logB)
```

where:

```text
witness space:  w in [0, 2^k)
threshold:      B = 2^logB
trace witness:  w >= B
```

The current benchmark rows are:

```text
(16,   32, 16)
(64,   32, 16)
(128,  32, 16)
(256,  40, 20)
(512,  40, 20)
(1024, 40, 20)
```

Dalek Bulletproofs require the range bit-size to be one of `8, 16, 32, 64`. The code pads the Bulletproof range size while keeping the logical benchmark parameter `k` unchanged:

```text
k <= 8        -> 8-bit range proof
k <= 16       -> 16-bit range proof
k <= 32       -> 32-bit range proof
k <= 64       -> 64-bit range proof
64 < k <= 128 -> 64-bit proofs over multiple 64-bit limbs
```

## Algorithm flow

### Setup

```text
okey := OKGen()
crs  := CRSGen(n, logB, k, okey.Opk)
ukey := UKGen(crs, w, v)
```

`OKGen` creates two opener public keys. `CRSGen` creates the commitment key, the ElGamal key for the OOM proof, and Bulletproof generators. `UKGen` creates the user public key:

```text
Upk = Commit(w; v)
```

### Sign

```text
signature := Sign(crs, crs.Opk, ukey.Upk, ukey.Usk, M, R)
```

The public circuit is:

```text
P = EvaluateCircuitP(Opk, M, R)
```

The benchmark circuit is intentionally simple:

```text
M = "context:audit"    => P(opk, M, R) = 1
otherwise              => P(opk, M, R) = 0
```

The branch is:

```text
w < B   and P = 0  -> R00
w < B   and P = 1  -> R01
w >= B  and P = 0  -> R10
w >= B  and P = 1  -> R11
```

The signer computes:

```text
V      = Commit(w;  r_V)
Vprime = Commit(w'; r_Vprime)
```

where:

```text
w' = B - 1 - w   if w < B
w' = w - B       if w >= B
```

The signature contains the OOM proof, range proofs for `V` and `Vprime`, and the OR proof for the selected branch.

### Verify

```text
ok := Verify(crs, signature, R)
```

Verification checks:

```text
1. OOM proof
2. range proof for V
3. range proof for Vprime
4. OR proof challenge consistency
5. OR sub-proofs
```

### Open

```text
bsgs := BuildDecodeBSGSTableRange(2^logB, 2^k - 1)
witness, userKey := Open(crs, okey.Osk, signature, bsgs)
```

The opening table stores only baby steps for decoding traceable witnesses `w >= B`. It uses baby-step giant-step over the interval `[2^logB, 2^k - 1]`, so the memory is about `sqrt(2^k - 2^logB)` group elements instead of the full interval size. Table generation is not counted in the reported opening time.

The benchmark reports two isolated opening columns:

```text
Open upk: decrypts the user-key ciphertext in the branch w < B and P = 1.
Open w:   decrypts and decodes the witness ciphertext in the branch w >= B and P = 0.
```
