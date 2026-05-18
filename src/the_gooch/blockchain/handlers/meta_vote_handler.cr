require "../../core/blockchain"
require "../../features/meta_vote"

# Handles committing legitimacy (meta-vote) blocks.
# Pure trust-score computation and verification stays in Features::MetaVote.
class TheGooch::Blockchain::Handlers::MetaVoteHandler
  def initialize(@blockchain : TheGooch::Blockchain)
  end

  def commit_round(target_block_hash : String,
                   scores : Array(TheGooch::Features::MetaVote::TrustScore)) : TheGooch::Block
    valid = scores.select { |s| TheGooch::Features::MetaVote.verify(target_block_hash, s) }
    values = valid.map(&.score)
    mean, variance = TheGooch::Features::MetaVote.aggregate(values)
    body = TheGooch::BlockBody::Legitimacy.new(target_block_hash, values, mean, variance)
    @blockchain.append_block("legitimacy", body.to_json, "", Array(String).new,
      TheGooch::Chain::MAIN_BRANCH)
  end
end
