require "big"
require "json"
require "./group"

# Pedersen commitments over the shared prime-order group: C(x, r) = g^x · h^r.
# Hiding: perfect (r uniform in Z_q). Binding: computational under DLOG.
module TheGooch::Crypto::Pedersen
  alias G = TheGooch::Crypto::Group

  struct Commitment
    include JSON::Serializable
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter c : BigInt

    def initialize(@c : BigInt)
    end
  end

  struct Opening
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter value : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter blinding : BigInt

    include JSON::Serializable

    def initialize(@value : BigInt, @blinding : BigInt)
    end
  end

  def self.commit(value : BigInt, blinding : BigInt = G.rand_scalar) : {Commitment, Opening}
    c = G.commit(value, blinding)
    {Commitment.new(c), Opening.new(value, blinding)}
  end

  def self.open(commitment : Commitment, opening : Opening) : Bool
    commitment.c == G.commit(opening.value, opening.blinding)
  end

  # Homomorphic addition: C(x1+x2, r1+r2) = C1 * C2 mod p.
  def self.add(c1 : Commitment, c2 : Commitment) : Commitment
    Commitment.new(G.mul(c1.c, c2.c))
  end
end
