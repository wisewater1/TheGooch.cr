require "../core/voter"
require "../core/vote"
require "../crypto/timelock"
require "../crypto/threshold_sig"
require "../config"
require "digest/sha256"

# Posthumous (pre-sealed future) voting.
#
# A voter pre-seals a ballot with either:
#   - TimeLockTrigger(t)     — Rivest squaring puzzle, opens after t squarings
#   - OracleTrigger(M, N, …) — opens when M-of-N attestors sign death notice
#   - Both — opens when EITHER condition is met.
#
# The OpenerService runs as a fiber; it polls pending ballots and emits opened
# votes into the supplied output channel for inclusion in a follow-up election.
module TheGooch::Features::Posthumous
  alias TimeLock = TheGooch::Crypto::TimeLock
  alias ThresholdSig = TheGooch::Crypto::ThresholdSig

  abstract struct Trigger
    abstract def kind : String
  end

  struct TimeLockTrigger < Trigger
    getter puzzle : TimeLock::Puzzle
    def initialize(@puzzle : TimeLock::Puzzle)
    end
    def kind : String
      "timelock"
    end
  end

  struct OracleTrigger < Trigger
    getter attest_message : String
    getter required : Int32
    getter dealing : ThresholdSig::Dealing
    def initialize(@attest_message, @required, @dealing)
    end
    def kind : String
      "oracle"
    end
  end

  struct SealedBallot
    getter id : String
    getter voter : TheGooch::Voter
    getter candidate : String
    getter trigger : Trigger

    def initialize(@voter, @candidate, @trigger)
      @id = Digest::SHA256.hexdigest("sealed|#{@voter.id}|#{@candidate}|#{Time.utc.to_unix_ns}")[0, 16]
    end

    def opens_with_oracle?(attestations : Array(ThresholdSig::Attestation)) : Bool
      case t = @trigger
      when OracleTrigger
        valid = attestations.count { |a| ThresholdSig.verify(t.attest_message, a) }
        valid >= t.required
      else
        false
      end
    end

    def opens_with_timelock_solve : Bytes?
      case t = @trigger
      when TimeLockTrigger
        TimeLock.solve(t.puzzle)
      else
        nil
      end
    end
  end

  def self.seal_with_timelock(voter : TheGooch::Voter, candidate : String, t : UInt64) : SealedBallot
    payload = "vote:#{candidate}".to_slice
    puzzle = TimeLock.seal(payload, t)
    SealedBallot.new(voter, candidate, TimeLockTrigger.new(puzzle))
  end

  def self.seal_with_oracle(voter : TheGooch::Voter, candidate : String,
                            attest_message : String, required : Int32, total : Int32) : SealedBallot
    dealing = ThresholdSig.deal(required, total)
    SealedBallot.new(voter, candidate, OracleTrigger.new(attest_message, required, dealing))
  end

  # Build a PlainVote (signed by the original voter) for inclusion when a
  # sealed ballot opens.
  def self.materialize(sealed : SealedBallot) : TheGooch::PlainVote
    message = "plain|#{sealed.voter.id}|#{sealed.candidate}|#{sealed.voter.region}"
    sig = sealed.voter.keypair.sign(message)
    TheGooch::PlainVote.new(sealed.voter.id, sealed.candidate, sig, sealed.voter.region)
  end
end
