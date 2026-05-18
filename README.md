# TheGooch.cr

Research-grade blockchain voting system written in Crystal, integrating six
novel governance primitives into a single coherent shard.

## Features

| Feature | What it does | Module |
| --- | --- | --- |
| Emotional Weighted Voting | Voters attach an intensity (0..1) to each vote. Intensity is Pedersen-committed with a ZK range proof; cost is quadratic in intensity (resists inflation). | `src/the_gooch/features/emotional.cr` |
| Posthumous Voting | Voters pre-seal future ballots; opened by Rivest time-lock squaring or by M-of-N oracle attestation (Shamir-shared key). | `src/the_gooch/features/posthumous.cr` |
| Meta-Vote / Legitimacy | Anonymous follow-up trust round on each result; mean & variance recorded in a dedicated block. | `src/the_gooch/features/meta_vote.cr` |
| Adversarial Minority Protection | Detects when the losing side is geographically concentrated (HHI) and the margin is narrow; defers finalization via a Deliberation block. | `src/the_gooch/features/minority.cr` |
| Forking Democracy | When consensus is weak the chain DAG-splits into two branches; a later Reconciliation block (two parents) merges or solidifies the split. | `src/the_gooch/features/forking.cr` |
| Vote Decay | Outcome weights decay exponentially (`exp(-λ·t)`); re-ratification by original voters resets the clock; expiry block fires below threshold. | `src/the_gooch/features/decay.cr` |

## Run the end-to-end demo

```sh
shards install            # only stdlib required; no shard deps in shard.yml
crystal run src/cli.cr -- demo
# or
bin/the_gooch demo --time-skew=1e9
```

The demo runs a deterministic 12-voter, 2-candidate election that fires every
feature in sequence and prints a `feature × block-index` summary.

## Cryptographic primitives

All built on a single 2048-bit safe-prime group (RFC 3526 Group 14):
- **Schnorr signatures** for voters and meta-vote ephemerals.
- **Pedersen commitments** for intensity hiding.
- **Bit-decomposition OR-proof range proofs** (Fiat-Shamir) for intensity ∈ [0, 2^bits).
- **Shamir secret sharing** over the group's prime-order subfield.
- **Trusted-dealer threshold attestation** (Shamir-shared Schnorr seed reconstruction).
- **Rivest-Shamir-Wagner time-lock** via repeated squaring; raw `libgmp` FFI on the hot loop, with a Crystal `BigInt` fallback (`-Dno_gmp`).

## Caveats — this is research code

- The demo's RSA-like modulus `N` has known factorization (no trusted-setup
  ceremony). A real time-lock deployment needs MPC trusted setup.
- Threshold attestation is *trusted-dealer Shamir reconstruction*, not true
  threshold-ECDSA (GG18/CMP). Documented as such.
- Meta-vote anonymity is approximated by ephemeral pre-registered keys; it is
  vulnerable to traffic analysis. Real anonymity requires ring/group sigs.
- Range proofs are O(n·bits) per vote. Bulletproofs (O(log n)) are out of scope.

## Layout

```
src/
  the_gooch.cr                  umbrella
  cli.cr                        demo|validate|version
  the_gooch/
    config.cr                   all hardcoded thresholds
    crypto/                     hash, Schnorr, Pedersen, range proof, Shamir, threshold sig, time-lock
    core/                       voter, vote, merkle, block, chain (DAG), blockchain (facade)
    features/                   six novel features
    tally/                      weighted tally engine
    demo/scenario.cr            deterministic end-to-end demo
spec/                           per-module specs + integration spec
```

## Testing

```sh
crystal spec
```

Specs avoid the slow time-lock T by using `Config::TIMELOCK_SPEC_T = 1000`.
The integration spec runs the demo scenario and asserts every `BlockBody`
variant is present in the final chain.

## License

MIT.
