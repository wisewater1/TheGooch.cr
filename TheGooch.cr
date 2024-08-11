require "openssl"
require "json"
require "digest/sha2"
require "concurrent"
require "time"

# ECC for Digital Signatures
class KeyPair
  getter :private_key, :public_key

  def initialize
    @private_key = OpenSSL::PKey::EC.generate("prime256v1")
    @public_key = @private_key.public_key
  end

  def sign(message : String)
    digest = OpenSSL::Digest::SHA256.new
    @private_key.dsa_sign_asn1(digest.digest(message))
  end

  def self.verify(public_key : OpenSSL::PKey::EC::PublicKey, message : String, signature : Bytes)
    digest = OpenSSL::Digest::SHA256.new
    public_key.dsa_verify_asn1(digest.digest(message), signature)
  end
end

# Voter class with unique ID
class Voter
  property id : String
  property key_pair : KeyPair

  def initialize(id : String)
    @id = id
    @key_pair = KeyPair.new
  end
end

# Vote class containing voter ID, candidate, and signature
class Vote
  property voter_id : String
  property candidate : String
  property signature : Bytes

  def initialize(voter_id : String, candidate : String, signature : Bytes)
    @voter_id = voter_id
    @candidate = candidate
    @signature = signature
  end

  def to_json
    {"voter_id" => @voter_id, "candidate" => @candidate, "signature" => @signature.hexstring}.to_json
  end

  def self.from_json(json : String)
    parsed = JSON.parse(json)
    Vote.new(parsed["voter_id"], parsed["candidate"], Bytes.new(parsed["signature"].hexstring))
  end

  def verify(public_key : OpenSSL::PKey::EC::PublicKey) : Bool
    KeyPair.verify(public_key, "#{@voter_id}#{@candidate}", @signature)
  end
end

# Merkle Tree for vote storage
class MerkleNode
  property hash : String
  property left : MerkleNode?
  property right : MerkleNode?

  def initialize(hash : String, left : MerkleNode? = nil, right : MerkleNode? = nil)
    @hash = hash
    @left = left
    @right = right
  end
end

class MerkleTree
  property root : MerkleNode?

  def initialize(votes : Array(Vote))
    @root = build_tree(votes.map { |vote| Digest::SHA256.hexdigest(vote.to_json) })
  end

  def build_tree(hashes : Array(String)) : MerkleNode?
    return nil if hashes.empty?
    return MerkleNode.new(hashes[0]) if hashes.size == 1

    mid = hashes.size // 2
    left = build_tree(hashes[0, mid])
    right = build_tree(hashes[mid, hashes.size])
    MerkleNode.new(Digest::SHA256.hexdigest(left.hash + right.hash), left, right)
  end
end

# Blockchain-inspired ledger
class Block
  property timestamp : Time
  property votes : Array(Vote)
  property previous_hash : String
  property merkle_root : String
  property hash : String

  def initialize(votes : Array(Vote), previous_hash : String)
    @timestamp = Time.now
    @votes = votes
    @previous_hash = previous_hash
    @merkle_root = MerkleTree.new(votes).root.try &.hash || ""
    @hash = Digest::SHA256.hexdigest("#{@timestamp}#{@votes.to_json}#{@previous_hash}#{@merkle_root}")
  end
end

class Blockchain
  property chain : Array(Block)

  def initialize
    @chain = [] of Block
    create_genesis_block
  end

  def create_genesis_block
    @chain << Block.new([] of Vote, "0")
  end

  def add_block(votes : Array(Vote))
    previous_hash = @chain.last.hash
    @chain << Block.new(votes, previous_hash)
  end

  def validate_chain : Bool
    @chain.each_with_index do |block, index|
      next if index == 0 # skip genesis block
      previous_block = @chain[index - 1]
      return false if block.previous_hash != previous_block.hash
      return false if block.hash != Digest::SHA256.hexdigest("#{block.timestamp}#{block.votes.to_json}#{block.previous_hash}#{block.merkle_root}")
    end
    true
  end
end

# Simulate voting with concurrency
class VotingSystem
  property blockchain : Blockchain
  property voters : Array(Voter)

  def initialize(voters : Array(Voter))
    @blockchain = Blockchain.new
    @voters = voters
  end

  def cast_votes
    vote_pool = Concurrent::Array.new
    @voters.each do |voter|
      Concurrent::Future.new do
        candidate = ["Alice", "Bob", "Charlie"].sample
        message = "#{voter.id}#{candidate}"
        signature = voter.key_pair.sign(message)
        vote = Vote.new(voter.id, candidate, signature)
        if vote.verify(voter.key_pair.public_key)
          vote_pool << vote
        end
      end.execute
    end
    Concurrent.global_io_pool.wait_for_termination
    @blockchain.add_block(vote_pool)
  end

  def verify_integrity
    @blockchain.validate_chain
  end
end

# Example usage
voters = ["voter1", "voter2", "voter3", "voter4"].map { |id| Voter.new(id) }
voting_system = VotingSystem.new(voters)
voting_system.cast_votes
puts voting_system.verify_integrity ? "Blockchain is valid." : "Blockchain is compromised."
