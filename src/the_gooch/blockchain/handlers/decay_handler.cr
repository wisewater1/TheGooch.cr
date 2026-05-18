require "../../core/blockchain"
require "../../features/decay"

# Handles committing expiry and ratification blocks.
# Decay math (effective_weight, expired?) stays in Features::Decay.
class TheGooch::Blockchain::Handlers::DecayHandler
  def initialize(@blockchain : TheGooch::Blockchain)
  end

  def scan(now : Time) : Array(TheGooch::Block)
    expired = [] of TheGooch::Block
    @blockchain.chain.each do |block|
      next unless block.body_kind == "tally"
      elapsed = (now.to_unix_ms - block.timestamp_ms).to_f / 1000.0
      eff = TheGooch::Features::Decay.effective_weight(1.0, elapsed)
      if TheGooch::Features::Decay.expired?(1.0, eff)
        body = TheGooch::BlockBody::Expiry.new(block.hash, eff)
        expired << @blockchain.append_block("expiry", body.to_json, "", Array(String).new,
          TheGooch::Chain::MAIN_BRANCH)
      end
    end
    expired
  end

  def ratify(target_hash : String, voter_ids : Array(String)) : TheGooch::Block
    body = TheGooch::BlockBody::Ratification.new(target_hash, voter_ids)
    @blockchain.append_block("ratification", body.to_json, "", Array(String).new,
      TheGooch::Chain::MAIN_BRANCH)
  end
end
