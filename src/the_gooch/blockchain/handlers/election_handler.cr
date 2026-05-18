require "../../core/blockchain"
require "../../core/vote"
require "../../core/merkle"
require "../../tally/engine"

# Handles committing election, tally, and deliberation blocks.
# Owns all blockchain.append_block calls related to the election lifecycle;
# keeps the body-kind strings out of call-site code.
class TheGooch::Blockchain::Handlers::ElectionHandler
  def initialize(@blockchain : TheGooch::Blockchain)
  end

  def commit_election(votes : Array(TheGooch::Vote), opened_ids : Array(String),
                      branch : String) : TheGooch::Block
    votes_json = votes.map(&.to_json)
    merkle_root = TheGooch::Merkle.root(votes_json)
    body = TheGooch::BlockBody::Election.new(votes_json, opened_ids)
    @blockchain.append_block("election", body.to_json, merkle_root, [] of String, branch)
  end

  def commit_tally(outcome : TheGooch::Tally::Outcome,
                   election_block_hash : String) : TheGooch::Block
    body = outcome.to_body(election_block_hash)
    @blockchain.append_block("tally", body.to_json, "", Array(String).new,
      TheGooch::Chain::MAIN_BRANCH)
  end

  def commit_deliberation(target_block_hash : String,
                          report : TheGooch::BlockBody::MinorityReport) : TheGooch::Block
    body = TheGooch::BlockBody::Deliberation.new(target_block_hash, report)
    @blockchain.append_block("deliberation", body.to_json, "", Array(String).new,
      TheGooch::Chain::MAIN_BRANCH)
  end
end
