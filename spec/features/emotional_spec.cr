require "../spec_helper"

describe TheGooch::Features::Emotional do
  it "enforces the quadratic voice-credit budget" do
    voter = TheGooch::Voter.new(id: "v1", credits: 20_u32, region: "north")
    # intensity=0.5 -> int=5 -> cost=25, exceeds budget=20
    expect_raises(ArgumentError) do
      TheGooch::Features::Emotional.cast(voter, "Calm", 0.5)
    end
  end

  it "produces an opening that opens the commitment" do
    voter = TheGooch::Voter.new(id: "v2", credits: 100_u32, region: "north")
    # intensity=0.5 -> int=5 -> cost=25
    result = TheGooch::Features::Emotional.cast(voter, "Calm", 0.5)
    TheGooch::Crypto::Pedersen.open(result.vote.intensity_commitment, result.opening).should be_true
  end

  it "weights candidates by revealed intensity" do
    voters = (1..3).map { |i| TheGooch::Voter.new(id: "v#{i}", credits: 100_u32, region: "n") }
    results = voters.map_with_index do |v, i|
      TheGooch::Features::Emotional.cast(v, i.zero? ? "Bold" : "Calm", 0.5)
    end
    votes = results.map(&.vote)
    openings = {} of String => TheGooch::Crypto::Pedersen::Opening
    results.each { |r| openings[r.vote.voter_id] = r.opening }
    tally = TheGooch::Features::Emotional.weighted_tally(votes, openings)
    tally["Calm"].should be > tally["Bold"]
  end
end
