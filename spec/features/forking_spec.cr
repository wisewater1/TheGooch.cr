require "../spec_helper"

private alias Forking = TheGooch::Features::Forking
private alias Config = TheGooch::Config

private def forking_handler(bc : TheGooch::Blockchain) : TheGooch::Blockchain::Handlers::ForkingHandler
  TheGooch::Blockchain::Handlers::ForkingHandler.new(bc)
end

describe TheGooch::Features::Forking do
  describe ".should_fork?" do
    it "returns true when raw margin is below threshold" do
      Forking.should_fork?(Config::FORK_MARGIN_THRESHOLD - 0.01, 0.5).should be_true
    end

    it "returns true when intensity gap is below threshold" do
      Forking.should_fork?(0.5, Config::INTENSITY_GAP_THRESHOLD - 0.01).should be_true
    end

    it "returns true when both are below threshold" do
      Forking.should_fork?(0.01, 0.01).should be_true
    end

    it "returns false when both are at or above their thresholds" do
      Forking.should_fork?(Config::FORK_MARGIN_THRESHOLD, Config::INTENSITY_GAP_THRESHOLD).should be_false
    end

    it "returns false for strong margins well above thresholds" do
      Forking.should_fork?(0.5, 0.5).should be_false
    end

    it "returns true at exactly zero for both" do
      Forking.should_fork?(0.0, 0.0).should be_true
    end
  end
end

describe TheGooch::Blockchain::Handlers::ForkingHandler do
  describe "#fork!" do
    it "appends a fork block to the main branch" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      _a, _b, fork_block = forking_handler(bc).fork!(parent, "weak margin")
      fork_block.body_kind.should eq("fork")
    end

    it "returns distinct branch ids containing the parent hash prefix" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      branch_a, branch_b, _block = forking_handler(bc).fork!(parent, "test")
      branch_a.should_not eq(branch_b)
      branch_a.should contain(parent[0, 6])
      branch_b.should contain(parent[0, 6])
    end

    it "creates heads for both new branches" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      branch_a, branch_b, _ = forking_handler(bc).fork!(parent, "test")
      bc.chain.head_of(branch_a).should_not be_nil
      bc.chain.head_of(branch_b).should_not be_nil
    end

    it "does not leave the chain in an invalid state" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      forking_handler(bc).fork!(parent, "test")
      bc.validate.ok?.should be_true
    end

    it "stores the criterion in the fork block body" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      _, _, fork_block = forking_handler(bc).fork!(parent, "weak intensity gap")
      parsed = TheGooch::BlockBody::Fork.from_json(fork_block.body_json)
      parsed.criterion.should eq("weak intensity gap")
    end
  end

  describe "#reconcile" do
    it "appends a reconciliation block referencing both branch heads as parents" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      h = forking_handler(bc)
      branch_a, branch_b, _ = h.fork!(parent, "test")
      rec = h.reconcile(branch_a, branch_b, "merge")
      rec.body_kind.should eq("reconciliation")
      rec.prev_hashes.size.should eq(2)
    end

    it "records the decision in the reconciliation body" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      h = forking_handler(bc)
      branch_a, branch_b, _ = h.fork!(parent, "test")
      rec = h.reconcile(branch_a, branch_b, "split")
      parsed = TheGooch::BlockBody::Reconciliation.from_json(rec.body_json)
      parsed.decision.should eq("split")
    end

    it "raises when a branch head is missing" do
      bc = TheGooch::Blockchain.new
      expect_raises(Exception, /missing branch heads/) do
        forking_handler(bc).reconcile("ghost-a", "ghost-b", "merge")
      end
    end

    it "leaves the chain valid after fork + reconcile" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      h = forking_handler(bc)
      branch_a, branch_b, _ = h.fork!(parent, "test")
      h.reconcile(branch_a, branch_b, "merge")
      bc.validate.ok?.should be_true
    end

    it "reconciliation block is a DAG merge node with both branch heads as parents" do
      bc = TheGooch::Blockchain.new
      parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      h = forking_handler(bc)
      branch_a, branch_b, _ = h.fork!(parent, "test")
      a_head = bc.chain.head_of(branch_a).not_nil!.hash
      b_head = bc.chain.head_of(branch_b).not_nil!.hash
      rec = h.reconcile(branch_a, branch_b, "merge")
      rec.prev_hashes.should contain(a_head)
      rec.prev_hashes.should contain(b_head)
    end
  end
end
