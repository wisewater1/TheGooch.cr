require "../spec_helper"

private alias Posthumous = TheGooch::Features::Posthumous
private alias ThresholdSig = TheGooch::Crypto::ThresholdSig
private alias Shamir = TheGooch::Crypto::Shamir

private def alice
  TheGooch::Voter.new("alice", TheGooch::KeyPair.new, region: "us-east")
end

describe TheGooch::Features::Posthumous do
  describe ".seal_with_timelock" do
    it "creates a SealedBallot with a TimeLock trigger" do
      ballot = Posthumous.seal_with_timelock(alice, "Candidate-A", TheGooch::Config::TIMELOCK_SPEC_T)
      ballot.voter.id.should eq("alice")
      ballot.candidate.should eq("Candidate-A")
      ballot.trigger.kind.should eq("timelock")
    end

    it "assigns a non-empty unique id" do
      b1 = Posthumous.seal_with_timelock(alice, "A", TheGooch::Config::TIMELOCK_SPEC_T)
      b2 = Posthumous.seal_with_timelock(alice, "A", TheGooch::Config::TIMELOCK_SPEC_T)
      b1.id.should_not be_empty
      b1.id.should_not eq(b2.id)
    end

    it "solves the timelock and returns a non-nil secret" do
      ballot = Posthumous.seal_with_timelock(alice, "A", TheGooch::Config::TIMELOCK_SPEC_T)
      result = ballot.opens_with_timelock_solve
      result.should_not be_nil
    end

    it "returns nil for opens_with_oracle? on a timelock ballot" do
      ballot = Posthumous.seal_with_timelock(alice, "A", TheGooch::Config::TIMELOCK_SPEC_T)
      ballot.opens_with_oracle?([] of ThresholdSig::Attestation).should be_false
    end
  end

  describe ".seal_with_oracle" do
    it "creates a SealedBallot with an Oracle trigger" do
      ballot = Posthumous.seal_with_oracle(alice, "B", "death-notice-alice", 2, 3)
      ballot.trigger.kind.should eq("oracle")
    end

    it "opens when M-of-N attestors provide valid signatures" do
      ballot = Posthumous.seal_with_oracle(alice, "B", "death-notice-alice", 2, 3)
      trigger = ballot.trigger.as(Posthumous::OracleTrigger)
      all_shares = trigger.dealing.shares

      # Any 2 of 3 shares suffice
      att = ThresholdSig.attest(trigger.attest_message, all_shares[0, 2], trigger.dealing.public_key)
      ballot.opens_with_oracle?([att]).should be_true
    end

    it "does not open with fewer than required attestors" do
      ballot = Posthumous.seal_with_oracle(alice, "B", "death-notice-alice", 2, 3)
      ballot.opens_with_oracle?([] of ThresholdSig::Attestation).should be_false
    end

    it "does not open with an attestation for a different message" do
      ballot = Posthumous.seal_with_oracle(alice, "B", "death-notice-alice", 2, 3)
      trigger = ballot.trigger.as(Posthumous::OracleTrigger)
      other = Posthumous.seal_with_oracle(alice, "B", "different-message", 2, 3)
      other_trigger = other.trigger.as(Posthumous::OracleTrigger)
      wrong_att = ThresholdSig.attest("different-message", other_trigger.dealing.shares[0, 2],
        other_trigger.dealing.public_key)
      ballot.opens_with_oracle?([wrong_att]).should be_false
    end

    it "returns nil for opens_with_timelock_solve on an oracle ballot" do
      ballot = Posthumous.seal_with_oracle(alice, "B", "msg", 2, 3)
      ballot.opens_with_timelock_solve.should be_nil
    end
  end

  describe ".materialize" do
    it "produces a PlainVote signed by the original voter" do
      ballot = Posthumous.seal_with_timelock(alice, "Candidate-A", TheGooch::Config::TIMELOCK_SPEC_T)
      vote = Posthumous.materialize(ballot)
      vote.voter_id.should eq("alice")
      vote.candidate.should eq("Candidate-A")
    end

    it "produces a vote whose signature verifies" do
      ballot = Posthumous.seal_with_timelock(alice, "Candidate-A", TheGooch::Config::TIMELOCK_SPEC_T)
      vote = Posthumous.materialize(ballot)
      msg = "plain|#{vote.voter_id}|#{vote.candidate}|#{ballot.voter.region}"
      TheGooch::KeyPair.verify(ballot.voter.keypair.public_key, msg, vote.signature).should be_true
    end
  end
end
