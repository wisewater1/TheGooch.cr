require "../config"
require "../core/blockchain"

# Forking Democracy.
#
# When consensus is weak (raw margin OR intensity gap below threshold), the
# chain splits: a Fork block is committed, then two branch heads are tracked
# in parallel. Voters opt into one branch. After the reconciliation window,
# a Reconciliation block (with two parents — a DAG merge) records whether
# the branches merge back or remain permanently split.
module TheGooch::Features::Forking
  alias Config = TheGooch::Config

  def self.should_fork?(raw_margin : Float64, intensity_gap : Float64) : Bool
    raw_margin < Config::FORK_MARGIN_THRESHOLD || intensity_gap < Config::INTENSITY_GAP_THRESHOLD
  end

  def self.fork!(blockchain : TheGooch::Blockchain, parent_hash : String,
                 criterion : String) : {String, String, TheGooch::Block}
    branch_a = "branch-A-#{parent_hash[0, 6]}"
    branch_b = "branch-B-#{parent_hash[0, 6]}"
    body = TheGooch::BlockBody::Fork.new(parent_hash, branch_a, branch_b, criterion)
    block = blockchain.append_block("fork", body.to_json, "", [parent_hash], TheGooch::Chain::MAIN_BRANCH)

    # Materialize both branch heads as empty placeholder bodies so the chain
    # has explicit heads to extend from.
    a_head = blockchain.append_block("genesis", TheGooch::BlockBody::Genesis.new("branch-A genesis").to_json,
                                     "", [block.hash], branch_a)
    b_head = blockchain.append_block("genesis", TheGooch::BlockBody::Genesis.new("branch-B genesis").to_json,
                                     "", [block.hash], branch_b)

    {branch_a, branch_b, block}
  end

  def self.reconcile(blockchain : TheGooch::Blockchain, branch_a : String,
                     branch_b : String, decision : String) : TheGooch::Block
    a_head = blockchain.chain.head_of(branch_a)
    b_head = blockchain.chain.head_of(branch_b)
    raise "missing branch heads" unless a_head && b_head
    body = TheGooch::BlockBody::Reconciliation.new(a_head.hash, b_head.hash, decision)
    blockchain.append_block("reconciliation", body.to_json, "",
                            [a_head.hash, b_head.hash], TheGooch::Chain::MAIN_BRANCH)
  end
end
