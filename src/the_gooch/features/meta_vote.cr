require "../core/voter"
require "../crypto/keypair"

# Meta-vote / legitimacy round — pure computation only.
# Blockchain mutation (commit_round) lives in
# TheGooch::Blockchain::Handlers::MetaVoteHandler.
#
# Anonymity is approximated by ephemeral keys voters register ahead of the
# round (documented research limitation — not a real ring sig).
module TheGooch::Features::MetaVote
  struct TrustScore
    include JSON::Serializable
    getter ephemeral_pubkey : String
    getter score : Float64
    getter signature : TheGooch::KeyPair::Signature

    def initialize(@ephemeral_pubkey, @score, @signature)
    end
  end

  def self.cast(score : Float64, target_block_hash : String) : {TrustScore, TheGooch::KeyPair}
    raise ArgumentError.new("score out of [0,1]") if score < 0.0 || score > 1.0
    ephemeral = TheGooch::KeyPair.new
    msg = "trust|#{target_block_hash}|#{score}"
    sig = ephemeral.sign(msg)
    {TrustScore.new(ephemeral.public_key.to_s(16), score, sig), ephemeral}
  end

  def self.verify(target_block_hash : String, ts : TrustScore) : Bool
    pubkey = BigInt.new(ts.ephemeral_pubkey, 16)
    msg = "trust|#{target_block_hash}|#{ts.score}"
    TheGooch::KeyPair.verify(pubkey, msg, ts.signature)
  end

  def self.aggregate(scores : Array(Float64)) : {Float64, Float64}
    return {0.0, 0.0} if scores.empty?
    mean = scores.sum / scores.size
    variance = scores.map { |s| (s - mean) ** 2 }.sum / scores.size
    {mean, variance}
  end
end
