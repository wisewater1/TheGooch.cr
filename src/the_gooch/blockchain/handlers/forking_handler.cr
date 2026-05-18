require "../../core/blockchain"

# Handles committing fork and reconciliation blocks to the DAG.
# Pure computation (should_fork?) stays in Features::Forking.
class TheGooch::Blockchain::Handlers::ForkingHandler
  def initialize(@blockchain : TheGooch::Blockchain)
  end

  def fork!(parent_hash : String, criterion : String) : {String, String, TheGooch::Block}
    branch_a = "branch-A-#{parent_hash[0, 6]}"
    branch_b = "branch-B-#{parent_hash[0, 6]}"
    body = TheGooch::BlockBody::Fork.new(parent_hash, branch_a, branch_b, criterion)
    block = @blockchain.append_block("fork", body.to_json, "", [parent_hash],
      TheGooch::Chain::MAIN_BRANCH)

    # Materialize both branch heads so the chain has explicit heads to extend from.
    @blockchain.append_block("genesis",
      TheGooch::BlockBody::Genesis.new("branch-A genesis").to_json, "", [block.hash], branch_a)
    @blockchain.append_block("genesis",
      TheGooch::BlockBody::Genesis.new("branch-B genesis").to_json, "", [block.hash], branch_b)

    {branch_a, branch_b, block}
  end

  def reconcile(branch_a : String, branch_b : String, decision : String) : TheGooch::Block
    a_head = @blockchain.chain.head_of(branch_a)
    b_head = @blockchain.chain.head_of(branch_b)
    raise "missing branch heads" unless a_head && b_head
    body = TheGooch::BlockBody::Reconciliation.new(a_head.hash, b_head.hash, decision)
    @blockchain.append_block("reconciliation", body.to_json, "",
      [a_head.hash, b_head.hash], TheGooch::Chain::MAIN_BRANCH)
  end
end
