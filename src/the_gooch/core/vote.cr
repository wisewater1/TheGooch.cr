require "json"
require "../crypto/keypair"
require "../crypto/pedersen"
require "../crypto/range_proof"

# Vote is a sum type discriminated by `kind`. The legacy script's broken
# JSON round-trip and Bytes handling are replaced here by JSON::Serializable
# with explicit converters.
abstract class TheGooch::Vote
  include JSON::Serializable

  property voter_id : String
  property candidate : String
  property signature : TheGooch::KeyPair::Signature
  property region : String?

  def initialize(@voter_id, @candidate, @signature, @region = nil)
  end

  abstract def canonical_message : String
  abstract def kind : String

  def verify(public_key : BigInt) : Bool
    TheGooch::KeyPair.verify(public_key, canonical_message, @signature)
  end
end

class TheGooch::PlainVote < TheGooch::Vote
  property kind : String = "plain"

  def initialize(@voter_id, @candidate, @signature, @region = nil)
    super
    @kind = "plain"
  end

  def canonical_message : String
    "plain|#{@voter_id}|#{@candidate}|#{@region || ""}"
  end
end

class TheGooch::EmotionalVote < TheGooch::Vote
  property kind : String = "emotional"
  property intensity_commitment : TheGooch::Crypto::Pedersen::Commitment
  property range_proof : TheGooch::Crypto::RangeProof::Proof
  property voice_credits_spent : UInt32

  def initialize(@voter_id, @candidate, @signature,
                 @intensity_commitment, @range_proof, @voice_credits_spent,
                 @region = nil)
    super(@voter_id, @candidate, @signature, @region)
    @kind = "emotional"
  end

  def canonical_message : String
    "emotional|#{@voter_id}|#{@candidate}|#{@intensity_commitment.c.to_s(16)}|#{@voice_credits_spent}|#{@region || ""}"
  end

  def proof_valid? : Bool
    TheGooch::Crypto::RangeProof.verify(@intensity_commitment, @range_proof, TheGooch::Config::PEDERSEN_BITS)
  end
end
