require "json"
require "digest/sha256"
require "./vote"
require "./merkle"

# A block carries a header plus a typed body. Body kinds:
#   :genesis, :election, :tally, :legitimacy, :deliberation,
#   :fork, :reconciliation, :ratification, :expiry
#
# Canonical bytes are deterministic: timestamp is unix-ms, body fields are
# serialized as sorted JSON, hash inputs are domain-separated.
class TheGooch::Block
  include JSON::Serializable

  property index : Int32
  property timestamp_ms : Int64
  property prev_hashes : Array(String) # supports DAG merges (Reconciliation)
  property body_kind : String
  property body_json : String
  property merkle_root : String
  property branch_id : String
  property hash : String

  def initialize(@index, @timestamp_ms, @prev_hashes, @body_kind, @body_json,
                 @merkle_root, @branch_id)
    @hash = compute_hash
  end

  def compute_hash : String
    Digest::SHA256.hexdigest(
      "block|v1|#{@index}|#{@timestamp_ms}|#{@prev_hashes.sort.join(",")}|" \
      "#{@body_kind}|#{@body_json}|#{@merkle_root}|#{@branch_id}"
    )
  end

  def valid_hash? : Bool
    @hash == compute_hash
  end
end

# Body payload structs — kept as JSON-serializable structs and stored in
# Block#body_json as their canonical JSON form.
module TheGooch::BlockBody
  struct Genesis
    include JSON::Serializable
    getter note : String
    def initialize(@note : String = "genesis")
    end
  end

  struct Election
    include JSON::Serializable
    getter votes_json : Array(String) # each is a Vote rendered as JSON
    getter opened_sealed_ids : Array(String)
    def initialize(@votes_json, @opened_sealed_ids)
    end
  end

  struct Tally
    include JSON::Serializable
    getter election_block_hash : String
    getter per_candidate_raw : Hash(String, Int32)
    getter per_candidate_weighted : Hash(String, Float64)
    getter winner : String
    getter raw_margin : Float64
    getter weighted_margin : Float64
    getter intensity_gap : Float64
    def initialize(@election_block_hash, @per_candidate_raw, @per_candidate_weighted,
                   @winner, @raw_margin, @weighted_margin, @intensity_gap)
    end
  end

  struct Legitimacy
    include JSON::Serializable
    getter target_block_hash : String
    getter trust_scores : Array(Float64)
    getter mean : Float64
    getter variance : Float64
    def initialize(@target_block_hash, @trust_scores, @mean, @variance)
    end
  end

  struct MinorityReport
    include JSON::Serializable
    getter losing_side : String
    getter hhi : Float64
    getter margin : Float64
    getter dominant_region : String
    def initialize(@losing_side, @hhi, @margin, @dominant_region)
    end
  end

  struct Deliberation
    include JSON::Serializable
    getter target_block_hash : String
    getter report : MinorityReport
    def initialize(@target_block_hash, @report)
    end
  end

  struct Fork
    include JSON::Serializable
    getter parent_hash : String
    getter branch_a_id : String
    getter branch_b_id : String
    getter criterion : String
    def initialize(@parent_hash, @branch_a_id, @branch_b_id, @criterion)
    end
  end

  struct Reconciliation
    include JSON::Serializable
    getter branch_a_head : String
    getter branch_b_head : String
    getter decision : String # "merge" | "split"
    def initialize(@branch_a_head, @branch_b_head, @decision)
    end
  end

  struct Ratification
    include JSON::Serializable
    getter target_outcome_hash : String
    getter voter_ids : Array(String)
    def initialize(@target_outcome_hash, @voter_ids)
    end
  end

  struct Expiry
    include JSON::Serializable
    getter target_outcome_hash : String
    getter decayed_weight : Float64
    def initialize(@target_outcome_hash, @decayed_weight)
    end
  end
end
