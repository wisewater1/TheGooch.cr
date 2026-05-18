require "../core/voter"
require "../core/vote"
require "../crypto/pedersen"
require "../crypto/range_proof"
require "../config"

# Emotional weighted voting. Intensity is a Float 0..1, discretized to an
# integer 0..INTENSITY_SCALE, Pedersen-committed with a ZK range proof.
# Voice-credit cost is quadratic in the discretized intensity (Quadratic
# Voting): cost = intensity_int². Resists intensity inflation.
module TheGooch::Features::Emotional
  alias Pedersen = TheGooch::Crypto::Pedersen
  alias RangeProof = TheGooch::Crypto::RangeProof
  alias Config = TheGooch::Config

  struct CastResult
    getter vote : TheGooch::EmotionalVote
    getter opening : Pedersen::Opening

    def initialize(@vote, @opening)
    end
  end

  def self.cast(voter : TheGooch::Voter, candidate : String, intensity : Float64) : CastResult
    raise ArgumentError.new("intensity out of [0,1]") if intensity < 0.0 || intensity > 1.0
    int_value = (intensity * Config::INTENSITY_SCALE).to_i
    cost = (int_value * int_value).to_u32
    voter.spend(cost)

    value = BigInt.new(int_value)
    # The range proof derives the aggregate blinding; we then bind the value
    # commitment to that same blinding so verifier's bit-aggregation matches.
    proof, blinding = RangeProof.prove(value, Config::PEDERSEN_BITS)
    commit, opening = Pedersen.commit(value, blinding)

    message = "emotional|#{voter.id}|#{candidate}|#{commit.c.to_s(16)}|#{cost}|#{voter.region}"
    signature = voter.keypair.sign(message)

    vote = TheGooch::EmotionalVote.new(
      voter_id: voter.id,
      candidate: candidate,
      signature: signature,
      intensity_commitment: commit,
      range_proof: proof,
      voice_credits_spent: cost,
      region: voter.region
    )
    CastResult.new(vote, opening)
  end

  # Tally weighted by revealed intensities. Caller must verify openings
  # before invoking (we double-check here).
  def self.weighted_tally(votes : Array(TheGooch::EmotionalVote),
                          openings : Hash(String, Pedersen::Opening)) : Hash(String, Float64)
    tally = Hash(String, Float64).new(0.0)
    votes.each do |v|
      opening = openings[v.voter_id]?
      next unless opening
      next unless Pedersen.open(v.intensity_commitment, opening)
      weight = opening.value.to_f / Config::INTENSITY_SCALE
      tally[v.candidate] += weight
    end
    tally
  end

  def self.raw_tally(votes : Array(TheGooch::Vote)) : Hash(String, Int32)
    tally = Hash(String, Int32).new(0)
    votes.each { |v| tally[v.candidate] += 1 }
    tally
  end
end
