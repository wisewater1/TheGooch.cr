require "math"
require "../config"
require "../core/blockchain"

# Vote Decay.
#
# Each finalized outcome carries a created-at timestamp; effective weight is
# original_weight * exp(-λ · elapsed_seconds). Ratification (re-affirmation by
# the original voters) resets the clock. When effective_weight falls below
# DECAY_EXPIRY_WEIGHT × original, an Expiry block is emitted.
module TheGooch::Features::Decay
  alias Config = TheGooch::Config

  def self.effective_weight(original : Float64, elapsed_seconds : Float64,
                            lambda_ : Float64 = Config::DECAY_LAMBDA) : Float64
    original * Math.exp(-lambda_ * elapsed_seconds)
  end

  def self.expired?(original : Float64, effective : Float64,
                   threshold : Float64 = Config::DECAY_EXPIRY_WEIGHT) : Bool
    effective < original * threshold
  end

  def self.scan(blockchain : TheGooch::Blockchain, now : Time) : Array(TheGooch::Block)
    expired = [] of TheGooch::Block
    blockchain.chain.each do |block|
      next unless block.body_kind == "tally"
      elapsed = (now.to_unix_ms - block.timestamp_ms).to_f / 1000.0
      eff = effective_weight(1.0, elapsed)
      if expired?(1.0, eff)
        body = TheGooch::BlockBody::Expiry.new(block.hash, eff)
        expired << blockchain.append_block("expiry", body.to_json, "", [] of String,
                                           TheGooch::Chain::MAIN_BRANCH)
      end
    end
    expired
  end

  def self.ratify(blockchain : TheGooch::Blockchain, target_hash : String,
                  voter_ids : Array(String)) : TheGooch::Block
    body = TheGooch::BlockBody::Ratification.new(target_hash, voter_ids)
    blockchain.append_block("ratification", body.to_json, "", [] of String,
                            TheGooch::Chain::MAIN_BRANCH)
  end
end
