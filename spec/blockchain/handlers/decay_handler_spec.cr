require "../../spec_helper"

private alias DH = TheGooch::Blockchain::Handlers::DecayHandler
private alias EH = TheGooch::Blockchain::Handlers::ElectionHandler

describe TheGooch::Blockchain::Handlers::DecayHandler do
  describe "#scan" do
    it "returns empty array when there are no tally blocks" do
      bc = TheGooch::Blockchain.new
      DH.new(bc).scan(Time.utc).should be_empty
    end

    it "emits an expiry block for an old tally block" do
      bc = TheGooch::Blockchain.new
      # Commit a tally block first.
      voter = TheGooch::Voter.new(id: "v1", region: "north")
      result = TheGooch::Features::Emotional.cast(voter, "Calm", 0.5)
      openings = {voter.id => result.opening}
      votes = [result.vote] of TheGooch::Vote
      outcome = TheGooch::Tally.compute(votes, openings)
      election_blk = EH.new(bc).commit_election(votes, Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      EH.new(bc).commit_tally(outcome, election_blk.hash)

      # Fast-forward far enough to expire (lambda=1e-8, 1e10 seconds → well past threshold).
      future = Time.utc + 1_000_000_000.seconds
      expired = DH.new(bc).scan(future)
      expired.size.should eq(1)
      expired.first.body_kind.should eq("expiry")
    end

    it "does not emit expiry for a recent tally block" do
      bc = TheGooch::Blockchain.new
      voter = TheGooch::Voter.new(id: "v2", region: "south")
      result = TheGooch::Features::Emotional.cast(voter, "Bold", 0.4)
      openings = {voter.id => result.opening}
      votes = [result.vote] of TheGooch::Vote
      outcome = TheGooch::Tally.compute(votes, openings)
      election_blk = EH.new(bc).commit_election(votes, Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      EH.new(bc).commit_tally(outcome, election_blk.hash)

      # Only 1 second in the future — weight barely decays.
      DH.new(bc).scan(Time.utc + 1.second).should be_empty
    end
  end

  describe "#ratify" do
    it "appends a ratification block referencing the target hash" do
      bc = TheGooch::Blockchain.new
      blk = DH.new(bc).ratify("tally-hash-abc", ["v1", "v2", "v3"])
      blk.body_kind.should eq("ratification")
      parsed = TheGooch::BlockBody::Ratification.from_json(blk.body_json)
      parsed.target_outcome_hash.should eq("tally-hash-abc")
      parsed.voter_ids.should eq(["v1", "v2", "v3"])
    end

    it "leaves the chain valid after ratification" do
      bc = TheGooch::Blockchain.new
      DH.new(bc).ratify("some-hash", ["v1"])
      bc.validate.ok?.should be_true
    end
  end
end
