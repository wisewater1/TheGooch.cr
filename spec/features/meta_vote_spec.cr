require "../spec_helper"

private alias MetaVote = TheGooch::Features::MetaVote

describe TheGooch::Features::MetaVote do
  describe ".cast" do
    it "returns a TrustScore with the submitted score" do
      ts, _kp = MetaVote.cast(0.8, "deadbeef")
      ts.score.should eq(0.8)
    end

    it "returns an ephemeral keypair that matches the TrustScore pubkey" do
      ts, kp = MetaVote.cast(0.5, "deadbeef")
      ts.ephemeral_pubkey.should eq(kp.public_key.to_s(16))
    end

    it "uses a fresh ephemeral key each call (different pubkeys)" do
      ts1, _ = MetaVote.cast(0.5, "deadbeef")
      ts2, _ = MetaVote.cast(0.5, "deadbeef")
      ts1.ephemeral_pubkey.should_not eq(ts2.ephemeral_pubkey)
    end

    it "rejects score < 0" do
      expect_raises(ArgumentError) { MetaVote.cast(-0.1, "abc") }
    end

    it "rejects score > 1" do
      expect_raises(ArgumentError) { MetaVote.cast(1.01, "abc") }
    end

    it "accepts boundary scores 0.0 and 1.0" do
      ts0, _ = MetaVote.cast(0.0, "abc")
      ts1, _ = MetaVote.cast(1.0, "abc")
      ts0.score.should eq(0.0)
      ts1.score.should eq(1.0)
    end
  end

  describe ".verify" do
    it "accepts an honest TrustScore" do
      ts, _ = MetaVote.cast(0.7, "blockhash123")
      MetaVote.verify("blockhash123", ts).should be_true
    end

    it "rejects a TrustScore replayed against a different block hash" do
      ts, _ = MetaVote.cast(0.7, "blockhash123")
      MetaVote.verify("different-hash", ts).should be_false
    end

    it "rejects a TrustScore with a tampered score" do
      ts, _ = MetaVote.cast(0.7, "blockhash123")
      tampered = MetaVote::TrustScore.new(ts.ephemeral_pubkey, 0.9, ts.signature)
      MetaVote.verify("blockhash123", tampered).should be_false
    end
  end

  describe ".aggregate" do
    it "returns zero mean and zero variance for empty input" do
      mean, var = MetaVote.aggregate([] of Float64)
      mean.should eq(0.0)
      var.should eq(0.0)
    end

    it "computes the correct mean" do
      mean, _ = MetaVote.aggregate([0.4, 0.6, 0.8])
      mean.should be_close(0.6, 1e-10)
    end

    it "returns zero variance for identical scores" do
      _, var = MetaVote.aggregate([0.5, 0.5, 0.5])
      var.should be_close(0.0, 1e-10)
    end

    it "computes non-zero variance for spread scores" do
      _, var = MetaVote.aggregate([0.0, 1.0])
      var.should be_close(0.25, 1e-10)
    end
  end

  describe ".commit_round" do
    it "appends a legitimacy block with valid scores" do
      bc = TheGooch::Blockchain.new
      target = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      ts1, _ = MetaVote.cast(0.9, target)
      ts2, _ = MetaVote.cast(0.4, target)
      block = MetaVote.commit_round(bc, target, [ts1, ts2])
      block.body_kind.should eq("legitimacy")
    end

    it "filters out a TrustScore with a bad signature" do
      bc = TheGooch::Blockchain.new
      target = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      ts_good, _ = MetaVote.cast(0.9, target)
      ts_bad, _ = MetaVote.cast(0.9, "wrong-hash")
      block = MetaVote.commit_round(bc, target, [ts_good, ts_bad])
      parsed = TheGooch::BlockBody::Legitimacy.from_json(block.body_json)
      parsed.trust_scores.size.should eq(1)
    end

    it "leaves the chain valid after a legitimacy block" do
      bc = TheGooch::Blockchain.new
      target = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      ts, _ = MetaVote.cast(0.6, target)
      MetaVote.commit_round(bc, target, [ts])
      bc.validate.ok?.should be_true
    end
  end
end
