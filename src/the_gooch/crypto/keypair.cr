require "big"
require "json"
require "digest/sha256"
require "./group"

# Schnorr signatures over the shared prime-order group. Replaces the broken
# OpenSSL::PKey::EC code from the legacy script. Public-key verifiable; uses
# only Crystal stdlib + BigInt (libgmp via stdlib `big`).
class TheGooch::KeyPair
  alias G = TheGooch::Crypto::Group

  struct Signature
    include JSON::Serializable
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter r : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter s : BigInt

    def initialize(@r : BigInt, @s : BigInt)
    end
  end

  getter private_key : BigInt
  getter public_key : BigInt

  def initialize(@private_key : BigInt = G.rand_scalar)
    @public_key = G.g_pow(@private_key)
  end

  def self.from_private(x : BigInt) : KeyPair
    new(x)
  end

  def sign(message : String) : Signature
    k = G.rand_scalar
    r_point = G.g_pow(k)
    e = G.hash_to_scalar(r_point, @public_key, message)
    s = (k + e * @private_key) % G::Q
    Signature.new(r_point, s)
  end

  def self.verify(public_key : BigInt, message : String, sig : Signature) : Bool
    e = G.hash_to_scalar(sig.r, public_key, message)
    lhs = G.g_pow(sig.s)
    rhs = (sig.r * G.powmod(public_key, e, G::P)) % G::P
    lhs == rhs
  end

  def id : String
    Digest::SHA256.hexdigest(@public_key.to_s(16))[0, 16]
  end
end

# JSON converter for BigInt as decimal string.
module TheGooch::BigIntStringConverter
  def self.from_json(pull : JSON::PullParser) : BigInt
    BigInt.new(pull.read_string)
  end

  def self.to_json(value : BigInt, json : JSON::Builder)
    json.string(value.to_s)
  end
end
