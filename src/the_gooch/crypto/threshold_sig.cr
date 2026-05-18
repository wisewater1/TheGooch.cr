require "big"
require "json"
require "./group"
require "./keypair"
require "./shamir"

# Trusted-dealer threshold attestation. A dealer generates a Schnorr-like
# keypair, splits the private scalar via Shamir(k, n), and distributes shares
# to attestors. Any k attestors can reconstruct the secret and produce a
# signature ("attestation"). NOT a true threshold-ECDSA scheme — this is a
# research approximation appropriate for demos.
module TheGooch::Crypto::ThresholdSig
  alias G = TheGooch::Crypto::Group
  alias Shamir = TheGooch::Crypto::Shamir
  alias KeyPair = TheGooch::KeyPair

  struct Dealing
    getter public_key : BigInt
    getter shares : Array(Shamir::Share)

    def initialize(@public_key : BigInt, @shares : Array(Shamir::Share))
    end
  end

  struct Attestation
    include JSON::Serializable
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter public_key : BigInt
    getter signature : KeyPair::Signature
    getter signer_ids : Array(Int32)

    def initialize(@public_key : BigInt, @signature : KeyPair::Signature, @signer_ids : Array(Int32))
    end
  end

  def self.deal(k : Int32, n : Int32) : Dealing
    secret = G.rand_scalar
    pubkey = G.g_pow(secret)
    shares = Shamir.split(secret, k, n)
    Dealing.new(pubkey, shares)
  end

  def self.attest(message : String, shares : Array(Shamir::Share), pubkey : BigInt) : Attestation
    secret = Shamir.combine(shares)
    kp = KeyPair.from_private(secret)
    raise "reconstructed key mismatch" unless kp.public_key == pubkey
    sig = kp.sign(message)
    Attestation.new(pubkey, sig, shares.map { |s| s.x.to_i32 })
  end

  def self.verify(message : String, attestation : Attestation) : Bool
    KeyPair.verify(attestation.public_key, message, attestation.signature)
  end
end
