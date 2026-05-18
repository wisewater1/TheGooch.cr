require "big"
require "json"
require "./group"

# Shamir's secret sharing over GF(Q) (prime field of the group's subgroup
# order). Splits a secret s ∈ [0, Q) into n shares such that any k reconstruct.
module TheGooch::Crypto::Shamir
  alias G = TheGooch::Crypto::Group

  struct Share
    include JSON::Serializable
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter x : BigInt
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter y : BigInt

    def initialize(@x : BigInt, @y : BigInt)
    end
  end

  def self.split(secret : BigInt, k : Int32, n : Int32) : Array(Share)
    raise ArgumentError.new("k > n") if k > n
    raise ArgumentError.new("k < 1") if k < 1

    coeffs = [secret % G::Q]
    (k - 1).times { coeffs << G.rand_scalar }

    (1..n).map do |i|
      x = BigInt.new(i)
      y = eval_poly(coeffs, x)
      Share.new(x, y)
    end
  end

  def self.combine(shares : Array(Share)) : BigInt
    secret = BigInt.new(0)
    shares.each_with_index do |s_i, i|
      num = BigInt.new(1)
      den = BigInt.new(1)
      shares.each_with_index do |s_j, j|
        next if i == j
        num = (num * (BigInt.new(0) - s_j.x)) % G::Q
        den = (den * (s_i.x - s_j.x)) % G::Q
      end
      term = (s_i.y * num * mod_inv(den, G::Q)) % G::Q
      secret = (secret + term) % G::Q
    end
    (secret % G::Q + G::Q) % G::Q
  end

  private def self.eval_poly(coeffs : Array(BigInt), x : BigInt) : BigInt
    result = BigInt.new(0)
    power = BigInt.new(1)
    coeffs.each do |c|
      result = (result + c * power) % G::Q
      power = (power * x) % G::Q
    end
    result
  end

  private def self.mod_inv(a : BigInt, m : BigInt) : BigInt
    G.powmod(((a % m) + m) % m, m - 2, m)
  end
end
