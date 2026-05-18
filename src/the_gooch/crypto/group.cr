require "big"
require "digest/sha256"
require "random/secure"

# Shared prime-order group parameters used by Schnorr signatures, Pedersen
# commitments, range proofs, and Shamir secret sharing.
#
# Demo parameters: 2048-bit safe prime p = 2q + 1 (RFC 3526 Group 14).
# Real deployments require a verifiable trusted setup for h.
module TheGooch::Crypto::Group
  P = BigInt.new(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" \
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" \
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" \
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" \
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" \
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16)

  Q = (P - 1) // 2

  ZERO = BigInt.new(0)
  ONE  = BigInt.new(1)
  TWO  = BigInt.new(2)

  # Square-and-multiply modular exponentiation.
  def self.powmod(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
    result = ONE
    b = base % mod
    e = exp
    while e > ZERO
      result = (result * b) % mod if (e & ONE) == ONE
      e >>= 1
      b = (b * b) % mod
    end
    result
  end

  # Generator g (= 4 = 2² lands in the order-q subgroup of QRs).
  G = BigInt.new(4)

  # h derived by hashing a seed and squaring into the QR subgroup. Discrete
  # log of h base g is presumed unknown.
  H = begin
    seed = Digest::SHA256.hexdigest("TheGooch/Crypto/Group/H/v1")
    base = BigInt.new(seed, 16) % P
    powmod(base, TWO, P)
  end

  def self.rand_scalar : BigInt
    bytes = Random::Secure.random_bytes(32)
    BigInt.new(bytes.hexstring, 16) % Q
  end

  def self.g_pow(x : BigInt) : BigInt
    powmod(G, x % Q, P)
  end

  def self.h_pow(x : BigInt) : BigInt
    powmod(H, x % Q, P)
  end

  def self.commit(value : BigInt, blinding : BigInt) : BigInt
    (g_pow(value) * h_pow(blinding)) % P
  end

  def self.mul(a : BigInt, b : BigInt) : BigInt
    (a * b) % P
  end

  def self.inv(a : BigInt) : BigInt
    # Fermat: a^(p-2) mod p for prime p
    powmod(a, P - 2, P)
  end

  def self.pow(base : BigInt, exp : BigInt) : BigInt
    powmod(base, exp % Q, P)
  end

  # Hash an arbitrary bytestring to a scalar in [0, Q).
  def self.hash_to_scalar(*parts) : BigInt
    digest = Digest::SHA256.new
    parts.each do |p|
      digest.update(p.to_s)
      digest.update("|")
    end
    BigInt.new(digest.final.hexstring, 16) % Q
  end
end
