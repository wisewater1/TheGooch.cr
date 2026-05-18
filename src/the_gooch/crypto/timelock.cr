require "big"
require "json"
require "random/secure"
require "digest/sha256"
require "./ffi/gmp"

# Rivest-Shamir-Wagner time-lock puzzle.
#
# Real-world setup uses a trapdoor: dealer knows N = p·q, computes
# φ(N) = (p-1)(q-1), then e = 2^t mod φ(N), then b = a^e mod N — fast.
# Solver lacks φ(N) and must square `t` times — slow.
#
# This demo deliberately OMITS the trapdoor: the dealer squares `t` times
# too. This makes seal/solve symmetric, but for the demo's small T values
# that's negligible, and it lets us use any composite N without a trusted
# setup ceremony for the primes. The cryptographic point — that the solver
# is forced through `t` sequential squarings — is preserved.
module TheGooch::Crypto::TimeLock
  # 2048-bit composite of unknown factorization (RFC 3526 Group 14 prime,
  # multiplied by an independent prime-shaped hex chunk). For demo only.
  DEMO_N = BigInt.new(
    "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F" \
    "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37" \
    "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64" \
    "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4" \
    "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754" \
    "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4" \
    "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F" \
    "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B",
    16)

  struct Puzzle
    include JSON::Serializable
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter n : BigInt
    getter t : UInt64
    @[JSON::Field(converter: TheGooch::BigIntStringConverter)]
    getter a : BigInt
    getter ciphertext_hex : String

    def initialize(@n : BigInt, @t : UInt64, @a : BigInt, @ciphertext_hex : String)
    end
  end

  def self.seal(plaintext : Bytes, t : UInt64, n : BigInt = DEMO_N) : Puzzle
    a = random_in_n(n)
    b = a % n
    t.times { b = (b * b) % n }
    key = Digest::SHA256.digest(b.to_s(16))
    ct = xor_bytes(plaintext, key)
    Puzzle.new(n, t, a, ct.hexstring)
  end

  # Slow path: squaring `t` times, no φ(N) shortcut.
  def self.solve(puzzle : Puzzle) : Bytes
    b = BigInt.new(0)
    {% if flag?(:no_gmp) %}
      b = puzzle.a % puzzle.n
      puzzle.t.times { b = (b * b) % puzzle.n }
    {% else %}
      modulus = TheGooch::Crypto::Mpz.from_bigint(puzzle.n)
      result = TheGooch::Crypto::Mpz.from_bigint(puzzle.a)
      puzzle.t.times do
        LibGMP.mul(result.to_unsafe, result.to_unsafe, result.to_unsafe)
        LibGMP.mod(result.to_unsafe, result.to_unsafe, modulus.to_unsafe)
      end
      b = result.to_bigint
    {% end %}
    key = Digest::SHA256.digest(b.to_s(16))
    ct = puzzle.ciphertext_hex.hexbytes
    xor_bytes(ct, key)
  end

  # Non-blocking solve: returns a channel that delivers the plaintext once
  # the squaring loop completes in a fresh fiber.
  def self.solve_async(puzzle : Puzzle) : Channel(Bytes)
    chan = Channel(Bytes).new(1)
    spawn do
      chan.send(solve(puzzle))
    end
    chan
  end

  private def self.random_in_n(n : BigInt) : BigInt
    bytes = Random::Secure.random_bytes(n.to_s(16).size // 2)
    (BigInt.new(bytes.hexstring, 16) % (n - 2)) + 2
  end

  private def self.xor_bytes(data : Bytes, key : Bytes) : Bytes
    out = Bytes.new(data.size)
    data.size.times do |i|
      out[i] = data[i] ^ key[i % key.size]
    end
    out
  end
end
