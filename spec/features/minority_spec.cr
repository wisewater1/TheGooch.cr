require "../spec_helper"

describe TheGooch::Features::Minority do
  it "computes HHI correctly" do
    # all in one region -> HHI = 1.0
    TheGooch::Features::Minority.compute_hhi({"north" => 5}).should eq(1.0)
    # evenly split across 4 -> HHI = 0.25
    TheGooch::Features::Minority.compute_hhi({"n" => 2, "s" => 2, "e" => 2, "w" => 2}).should be_close(0.25, 1e-9)
  end

  it "triggers when minority is concentrated AND margin narrow" do
    # 6 votes for A, 4 for B, all 4 B voters in "south"
    votes = [] of TheGooch::Vote
    6.times do |i|
      kp = TheGooch::KeyPair.new
      sig = kp.sign("plain|vA#{i}|A|north")
      votes << TheGooch::PlainVote.new("vA#{i}", "A", sig, "north")
    end
    4.times do |i|
      kp = TheGooch::KeyPair.new
      sig = kp.sign("plain|vB#{i}|B|south")
      votes << TheGooch::PlainVote.new("vB#{i}", "B", sig, "south")
    end
    raw = {"A" => 6, "B" => 4}
    margin = 0.02 # narrow
    assess = TheGooch::Features::Minority.assess(votes, raw, margin)
    assess.trigger.should be_true
    assess.report.not_nil!.dominant_region.should eq("south")
  end
end
