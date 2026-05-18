require "digest/sha256"

# Canonical Merkle tree with odd-leaf duplication (bitcoin-style). Replaces
# the legacy unbalanced split. Provides proofs for off-chain verification.
module TheGooch::Merkle
  alias Proof = Array(NamedTuple(sibling: String, side: Symbol))

  def self.root(leaves : Array(String)) : String
    return "" if leaves.empty?
    layer = leaves.map { |l| Digest::SHA256.hexdigest(l) }
    while layer.size > 1
      layer << layer.last if layer.size.odd?
      layer = (0...layer.size).step(2).map { |i| Digest::SHA256.hexdigest(layer[i] + layer[i + 1]) }.to_a
    end
    layer.first
  end

  def self.proof_for(leaves : Array(String), index : Int32) : Proof
    raise IndexError.new if index < 0 || index >= leaves.size
    layer = leaves.map { |l| Digest::SHA256.hexdigest(l) }
    proof = Proof.new
    idx = index
    while layer.size > 1
      layer << layer.last if layer.size.odd?
      sib_idx = idx.even? ? idx + 1 : idx - 1
      side = idx.even? ? :right : :left
      proof << {sibling: layer[sib_idx], side: side}
      layer = (0...layer.size).step(2).map { |i| Digest::SHA256.hexdigest(layer[i] + layer[i + 1]) }.to_a
      idx //= 2
    end
    proof
  end

  def self.verify(leaf : String, proof : Proof, root : String) : Bool
    cur = Digest::SHA256.hexdigest(leaf)
    proof.each do |step|
      cur = step[:side] == :right ? Digest::SHA256.hexdigest(cur + step[:sibling]) : Digest::SHA256.hexdigest(step[:sibling] + cur)
    end
    cur == root
  end
end
