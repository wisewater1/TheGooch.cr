require "../../spec_helper"

private alias EH = TheGooch::Blockchain::Handlers::ElectionHandler

describe TheGooch::Blockchain::Handlers::ElectionHandler do
  describe "#commit_election" do
    it "appends an election block with the correct kind" do
      bc = TheGooch::Blockchain.new
      voter = TheGooch::Voter.new(id: "v1", region: "north")
      result = TheGooch::Features::Emotional.cast(voter, "Calm", 0.5)
      blk = EH.new(bc).commit_election([result.vote], Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      blk.body_kind.should eq("election")
    end

    it "sets the merkle root to the hash of the vote set" do
      bc = TheGooch::Blockchain.new
      voter = TheGooch::Voter.new(id: "v2", region: "south")
      result = TheGooch::Features::Emotional.cast(voter, "Bold", 0.4)
      blk = EH.new(bc).commit_election([result.vote], Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      blk.merkle_root.should_not be_empty
    end

    it "records opened_ids in the block body" do
      bc = TheGooch::Blockchain.new
      blk = EH.new(bc).commit_election([] of TheGooch::Vote, ["id-abc"], TheGooch::Chain::MAIN_BRANCH)
      parsed = TheGooch::BlockBody::Election.from_json(blk.body_json)
      parsed.opened_sealed_ids.should eq(["id-abc"])
    end
  end

  describe "#commit_tally" do
    it "appends a tally block referencing the election block" do
      bc = TheGooch::Blockchain.new
      voter = TheGooch::Voter.new(id: "v3", region: "east")
      result = TheGooch::Features::Emotional.cast(voter, "Calm", 0.6)
      openings = {voter.id => result.opening}
      votes = [result.vote] of TheGooch::Vote
      outcome = TheGooch::Tally.compute(votes, openings)
      election_hash = "abc123"
      blk = EH.new(bc).commit_tally(outcome, election_hash)
      blk.body_kind.should eq("tally")
      parsed = TheGooch::BlockBody::Tally.from_json(blk.body_json)
      parsed.election_block_hash.should eq(election_hash)
    end
  end

  describe "#commit_deliberation" do
    it "appends a deliberation block referencing the target" do
      bc = TheGooch::Blockchain.new
      report = TheGooch::BlockBody::MinorityReport.new(
        losing_side: "Bold", hhi: 0.8, margin: 0.03, dominant_region: "south"
      )
      blk = EH.new(bc).commit_deliberation("target-hash-xyz", report)
      blk.body_kind.should eq("deliberation")
      parsed = TheGooch::BlockBody::Deliberation.from_json(blk.body_json)
      parsed.target_block_hash.should eq("target-hash-xyz")
      parsed.report.hhi.should be_close(0.8, 1e-10)
    end
  end
end
