require "../spec_helper"

private alias G = TheGooch::Crypto::Group
private alias Pedersen = TheGooch::Crypto::Pedersen
private alias RangeProof = TheGooch::Crypto::RangeProof

private def commit_with(value : BigInt, blinding : BigInt) : Pedersen::Commitment
  Pedersen::Commitment.new(G.commit(value, blinding))
end

describe TheGooch::Crypto::RangeProof do
  describe ".prove" do
    it "rejects negative values" do
      expect_raises(ArgumentError) { RangeProof.prove(BigInt.new(-1), 4) }
    end

    it "rejects values >= 2^bits" do
      expect_raises(ArgumentError) { RangeProof.prove(BigInt.new(16), 4) }
    end

    it "accepts the boundary value 2^bits - 1" do
      proof, r = RangeProof.prove(BigInt.new(15), 4)
      RangeProof.verify(commit_with(BigInt.new(15), r), proof, 4).should be_true
    end

    it "accepts zero" do
      proof, r = RangeProof.prove(BigInt.new(0), 4)
      RangeProof.verify(commit_with(BigInt.new(0), r), proof, 4).should be_true
    end
  end

  describe ".verify" do
    it "accepts an honest proof for a mid-range value" do
      proof, r = RangeProof.prove(BigInt.new(5), 4)
      RangeProof.verify(commit_with(BigInt.new(5), r), proof, 4).should be_true
    end

    it "rejects a proof when the value commitment uses a different value" do
      proof, r = RangeProof.prove(BigInt.new(5), 4)
      RangeProof.verify(commit_with(BigInt.new(6), r), proof, 4).should be_false
    end

    it "rejects a proof when the value commitment uses a different blinding" do
      proof, r = RangeProof.prove(BigInt.new(5), 4)
      wrong_r = (r + BigInt.new(1)) % G::Q
      RangeProof.verify(commit_with(BigInt.new(5), wrong_r), proof, 4).should be_false
    end

    it "rejects when bit count doesn't match the proof length" do
      proof, r = RangeProof.prove(BigInt.new(5), 4)
      RangeProof.verify(commit_with(BigInt.new(5), r), proof, 5).should be_false
      RangeProof.verify(commit_with(BigInt.new(5), r), proof, 3).should be_false
    end

    it "rejects a tampered bit commitment" do
      proof, r = RangeProof.prove(BigInt.new(5), 4)
      bp = proof.bits[0]
      tampered = RangeProof::BitProof.new(
        (bp.commitment * BigInt.new(2)) % G::P,
        bp.a0, bp.a1, bp.c0, bp.c1, bp.z0, bp.z1
      )
      bits = proof.bits.dup
      bits[0] = tampered
      bad = RangeProof::Proof.new(bits, proof.aggregate_blinding)
      RangeProof.verify(commit_with(BigInt.new(5), r), bad, 4).should be_false
    end

    it "rejects a tampered response (z0)" do
      proof, r = RangeProof.prove(BigInt.new(5), 4)
      bp = proof.bits[1]
      tampered = RangeProof::BitProof.new(
        bp.commitment, bp.a0, bp.a1, bp.c0, bp.c1,
        (bp.z0 + BigInt.new(1)) % G::Q, bp.z1
      )
      bits = proof.bits.dup
      bits[1] = tampered
      bad = RangeProof::Proof.new(bits, proof.aggregate_blinding)
      RangeProof.verify(commit_with(BigInt.new(5), r), bad, 4).should be_false
    end

    it "rejects a tampered challenge split (c0)" do
      proof, r = RangeProof.prove(BigInt.new(5), 4)
      bp = proof.bits[0]
      tampered = RangeProof::BitProof.new(
        bp.commitment, bp.a0, bp.a1,
        (bp.c0 + BigInt.new(1)) % G::Q, bp.c1, bp.z0, bp.z1
      )
      bits = proof.bits.dup
      bits[0] = tampered
      bad = RangeProof::Proof.new(bits, proof.aggregate_blinding)
      RangeProof.verify(commit_with(BigInt.new(5), r), bad, 4).should be_false
    end

    it "rejects a forged bit commitment that isn't 0 or 1" do
      # Hand-craft a commitment to 2 and try to prove it's a bit. Without the
      # OR-witness for either branch, no honest prover transcript exists.
      r = G.rand_scalar
      forged_c = G.commit(BigInt.new(2), r)
      bp = RangeProof::BitProof.new(
        forged_c,
        G.rand_scalar, G.rand_scalar, G.rand_scalar, G.rand_scalar,
        G.rand_scalar, G.rand_scalar
      )
      proof = RangeProof::Proof.new([bp], BigInt.new(0))
      RangeProof.verify(Pedersen::Commitment.new(forged_c), proof, 1).should be_false
    end
  end

  describe "soundness" do
    it "produces a proof that's bound to its value (swapping value commitments fails)" do
      p5, r5 = RangeProof.prove(BigInt.new(5), 4)
      _p6, r6 = RangeProof.prove(BigInt.new(6), 4)
      # p5's bit commitments encode 5; the commitment for 6 with r6 can't match.
      RangeProof.verify(commit_with(BigInt.new(6), r6), p5, 4).should be_false
    end

    it "different proofs of the same value still verify (randomized blindings)" do
      p1, r1 = RangeProof.prove(BigInt.new(7), 4)
      p2, r2 = RangeProof.prove(BigInt.new(7), 4)
      r1.should_not eq(r2)
      RangeProof.verify(commit_with(BigInt.new(7), r1), p1, 4).should be_true
      RangeProof.verify(commit_with(BigInt.new(7), r2), p2, 4).should be_true
    end
  end

  describe "JSON serialization" do
    it "round-trips a proof and preserves verifiability" do
      proof, r = RangeProof.prove(BigInt.new(9), 4)
      json = proof.to_json
      parsed = RangeProof::Proof.from_json(json)
      RangeProof.verify(commit_with(BigInt.new(9), r), parsed, 4).should be_true
    end
  end
end
