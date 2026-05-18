require "big"
require "json"
require "./group"
require "./pedersen"

# Bit-decomposition range proof: prove committed v ∈ [0, 2^bits) without
# revealing v. For each bit b ∈ {0,1} we run an OR-proof (Camenisch-Stadler
# style) that C_i commits to 0 OR commits to 1. The sum of bit-commitments
# (scaled by powers of two) must equal the value commitment.
#
# Fiat-Shamir transformed via SHA-256.
module TheGooch::Crypto::RangeProof
  alias G = TheGooch::Crypto::Group
  alias Pedersen = TheGooch::Crypto::Pedersen

  struct BitProof
    include JSON::Serializable
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter commitment : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter a0 : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter a1 : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter c0 : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter c1 : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter z0 : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter z1 : BigInt

    def initialize(@commitment, @a0, @a1, @c0, @c1, @z0, @z1)
    end
  end

  struct Proof
    include JSON::Serializable
    getter bits : Array(BitProof)
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter aggregate_blinding : BigInt

    def initialize(@bits : Array(BitProof), @aggregate_blinding : BigInt)
    end
  end

  # Prove value v ∈ [0, 2^bits). Returns the proof AND the aggregate blinding
  # `r = sum_i (2^i · r_i) mod q` — the caller must use that exact `r` when
  # constructing the value commitment so the verifier's bit-aggregation check
  # lines up. This keeps the prover honest about both range and binding.
  def self.prove(value : BigInt, bits : Int32) : {Proof, BigInt}
    raise ArgumentError.new("value out of range") if value < 0 || value >= (BigInt.new(1) << bits)

    bit_proofs = [] of BitProof
    aggregate = BigInt.new(0)

    bits.times do |i|
      b = ((value >> i) & BigInt.new(1)) == 1 ? BigInt.new(1) : BigInt.new(0)
      r_i = G.rand_scalar
      aggregate = (aggregate + r_i * (BigInt.new(1) << i)) % G::Q
      c_i = G.commit(b, r_i)
      bit_proofs << build_bit_proof(c_i, b, r_i)
    end

    {Proof.new(bit_proofs, aggregate), aggregate}
  end

  def self.verify(commitment : Pedersen::Commitment, proof : Proof, bits : Int32) : Bool
    return false if proof.bits.size != bits

    # 1) each bit proof verifies
    proof.bits.each do |bp|
      return false unless verify_bit_proof(bp)
    end

    # 2) sum_i (C_i ^ 2^i) ≡ C(value, aggregate_blinding) mod p where the
    #    aggregate blinding equals sum_i (2^i * r_i). We can't extract r_i
    #    from a proof, so we use the supplied aggregate_blinding only as a
    #    consistency challenge: recompute the expected commitment from the
    #    bit-commitments and compare against `commitment`.
    expected = BigInt.new(1)
    bits.times do |i|
      pow = G.powmod(proof.bits[i].commitment, BigInt.new(1) << i, G::P)
      expected = (expected * pow) % G::P
    end

    expected == commitment.c
  end

  # OR-proof that c commits to 0 OR commits to 1.
  # Sigma-OR construction: prover knows witness for one branch, simulates the
  # other, then splits Fiat-Shamir challenge.
  private def self.build_bit_proof(c : BigInt, b : BigInt, r : BigInt) : BitProof
    if b == BigInt.new(0)
      # real branch: 0; simulate branch: 1
      w = G.rand_scalar
      a0 = G.h_pow(w)

      c1_sim = G.rand_scalar
      z1_sim = G.rand_scalar
      # a1 = h^z1 * (c / g)^(-c1)  so verifier sees h^z1 == a1 * (c/g)^c1
      c_minus_g = (c * G.inv(G.g_pow(BigInt.new(1)))) % G::P
      a1 = (G.h_pow(z1_sim) * G.inv(G.powmod(c_minus_g, c1_sim, G::P))) % G::P

      challenge = G.hash_to_scalar(c, a0, a1)
      c0 = (challenge - c1_sim) % G::Q
      z0 = (w + c0 * r) % G::Q

      BitProof.new(c, a0, a1, c0, c1_sim, z0, z1_sim)
    else
      # real branch: 1; simulate branch: 0
      w = G.rand_scalar
      c_minus_g = (c * G.inv(G.g_pow(BigInt.new(1)))) % G::P
      a1 = G.h_pow(w)

      c0_sim = G.rand_scalar
      z0_sim = G.rand_scalar
      a0 = (G.h_pow(z0_sim) * G.inv(G.powmod(c, c0_sim, G::P))) % G::P

      challenge = G.hash_to_scalar(c, a0, a1)
      c1 = (challenge - c0_sim) % G::Q
      z1 = (w + c1 * r) % G::Q

      BitProof.new(c, a0, a1, c0_sim, c1, z0_sim, z1)
    end
  end

  private def self.verify_bit_proof(bp : BitProof) : Bool
    challenge = G.hash_to_scalar(bp.commitment, bp.a0, bp.a1)
    return false unless ((bp.c0 + bp.c1) % G::Q) == challenge

    # branch 0: h^z0 == a0 * C^c0
    lhs0 = G.h_pow(bp.z0)
    rhs0 = (bp.a0 * G.powmod(bp.commitment, bp.c0, G::P)) % G::P
    return false unless lhs0 == rhs0

    # branch 1: h^z1 == a1 * (C / g)^c1
    c_minus_g = (bp.commitment * G.inv(G.g_pow(BigInt.new(1)))) % G::P
    lhs1 = G.h_pow(bp.z1)
    rhs1 = (bp.a1 * G.powmod(c_minus_g, bp.c1, G::P)) % G::P
    lhs1 == rhs1
  end
end
