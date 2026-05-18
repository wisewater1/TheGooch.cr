require "../core/blockchain"
require "../core/voter"
require "../core/vote"
require "../crypto/pedersen"
require "../crypto/threshold_sig"
require "../features/emotional"
require "../features/posthumous"
require "../features/meta_vote"
require "../features/minority"
require "../features/forking"
require "../features/decay"
require "../tally/engine"

# End-to-end deterministic election that exercises every feature.
#
# The scenario is intentionally rigged so that:
#   - the first round triggers minority protection (concentrated losing region)
#   - the re-run still triggers forking (narrow intensity gap)
#   - reconciliation merges the branches
#   - a meta-vote round records trust scores
#   - a time-skewed decay scan emits Expiry, then a Ratification resets it
module TheGooch::Demo
  REGIONS    = ["north", "south", "east", "west"]
  CANDIDATES = ["Calm", "Bold"]

  struct Result
    getter blockchain : TheGooch::Blockchain
    getter feature_blocks : Hash(String, Array(Int32))

    def initialize(@blockchain, @feature_blocks)
    end
  end

  def self.run(io : IO = STDOUT, time_skew_seconds : Float64 = 1.0e9,
               store : TheGooch::BlockStore::Base = TheGooch::BlockStore::Null.new) : Result
    blockchain = TheGooch::Blockchain.new(store)
    feature_blocks = Hash(String, Array(Int32)).new { |h, k| h[k] = [] of Int32 }

    log = ->(feature : String, message : String) do
      io.puts "[feature:#{feature}] #{message}"
    end

    voters = setup_voters(log)

    # --- Posthumous seals -----------------------------------------------------
    log.call("posthumous", "voter #{voters[10].id} seals future Bold vote with time-lock (T=#{TheGooch::Config::TIMELOCK_SPEC_T})")
    sealed_tl = TheGooch::Features::Posthumous.seal_with_timelock(
      voters[10], "Bold", TheGooch::Config::TIMELOCK_SPEC_T
    )

    attest_msg = "death-cert|voter=#{voters[11].id}|date=2026-05-18"
    log.call("posthumous", "voter #{voters[11].id} seals future Calm vote with 3-of-5 oracle attestation")
    sealed_oracle = TheGooch::Features::Posthumous.seal_with_oracle(
      voters[11], "Calm", attest_msg, TheGooch::Config::THRESHOLD_M, TheGooch::Config::THRESHOLD_N
    )

    # --- First election: rigged narrow margin --------------------------------
    log.call("emotional", "casting first round (10 living voters, varied intensities)")
    first_votes, first_openings = cast_first_round(voters)
    first_election = commit_election(blockchain, first_votes, Array(String).new,
      TheGooch::Chain::MAIN_BRANCH, log, feature_blocks)

    outcome = TheGooch::Tally.compute(first_votes, first_openings)
    log.call("tally", "first round raw=#{outcome.per_candidate_raw} weighted=#{outcome.per_candidate_weighted.transform_values { |v| v.round(2) }}")
    log.call("tally", "winner=#{outcome.winner} raw_margin=#{outcome.raw_margin.round(3)} intensity_gap=#{outcome.intensity_gap.round(3)}")

    # --- Minority assessment -------------------------------------------------
    assessment = TheGooch::Features::Minority.assess(
      first_votes.map(&.as(TheGooch::Vote)), outcome.per_candidate_raw, outcome.raw_margin
    )
    if assessment.trigger && (report = assessment.report)
      log.call("minority", "HHI=#{report.hhi.round(3)} concentrated in '#{report.dominant_region}' — deferring finalization")
      delib = TheGooch::BlockBody::Deliberation.new(first_election.hash, report)
      blk = blockchain.append_block("deliberation", delib.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      feature_blocks["minority"] << blk.index
    else
      log.call("minority", "no trigger; finalizing")
    end

    # --- Second election: deliberated, wider margin --------------------------
    log.call("emotional", "casting deliberated second round (same voters, shifted intensities)")
    second_votes, second_openings = cast_second_round(voters)

    # Open posthumous ballots between rounds.
    opened_ids = open_posthumous(sealed_tl, sealed_oracle, attest_msg, voters, second_votes, log)
    second_election = commit_election(blockchain, second_votes, opened_ids,
      TheGooch::Chain::MAIN_BRANCH, log, feature_blocks)

    outcome2 = TheGooch::Tally.compute(second_votes, second_openings)
    log.call("tally", "second round raw=#{outcome2.per_candidate_raw} winner=#{outcome2.winner} raw_margin=#{outcome2.raw_margin.round(3)} intensity_gap=#{outcome2.intensity_gap.round(3)}")
    tally_blk = blockchain.append_block("tally", outcome2.to_body(second_election.hash).to_json,
      "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
    feature_blocks["tally"] << tally_blk.index

    # --- Forking democracy ---------------------------------------------------
    if TheGooch::Features::Forking.should_fork?(outcome2.raw_margin, outcome2.intensity_gap)
      log.call("forking", "consensus weak — splitting chain")
      branch_a, branch_b, fork_blk = TheGooch::Features::Forking.fork!(
        blockchain, tally_blk.hash, "intensity_gap=#{outcome2.intensity_gap.round(3)}"
      )
      feature_blocks["forking"] << fork_blk.index
      log.call("forking", "branches: #{branch_a}, #{branch_b}")

      # short reconciliation window (skipped for demo determinism)
      log.call("forking", "reconciliation: merging branches")
      recon_blk = TheGooch::Features::Forking.reconcile(blockchain, branch_a, branch_b, "merge")
      feature_blocks["forking"] << recon_blk.index
    end

    # --- Meta-vote round -----------------------------------------------------
    log.call("meta_vote", "opening legitimacy round on tally #{tally_blk.hash[0, 12]}")
    trust_scores = voters.first(8).map_with_index do |_, i|
      score = 0.5 + (i * 0.05).clamp(0.0, 0.4)
      ts, _ = TheGooch::Features::MetaVote.cast(score, tally_blk.hash)
      ts
    end
    leg_blk = TheGooch::Features::MetaVote.commit_round(blockchain, tally_blk.hash, trust_scores)
    feature_blocks["meta_vote"] << leg_blk.index
    leg_body = TheGooch::BlockBody::Legitimacy.from_json(leg_blk.body_json)
    log.call("meta_vote", "trust mean=#{leg_body.mean.round(3)} variance=#{leg_body.variance.round(4)}")

    # --- Decay simulation ----------------------------------------------------
    log.call("decay", "fast-forwarding #{time_skew_seconds.to_i} seconds — scanning for expiry")
    future = Time.utc + time_skew_seconds.to_i64.seconds
    expiries = TheGooch::Features::Decay.scan(blockchain, future)
    expiries.each { |b| feature_blocks["decay"] << b.index }
    log.call("decay", "emitted #{expiries.size} expiry block(s)")

    if !expiries.empty?
      ratify_blk = TheGooch::Features::Decay.ratify(blockchain, tally_blk.hash, voters.first(6).map(&.id))
      feature_blocks["decay"] << ratify_blk.index
      log.call("decay", "ratified — clock reset")
    end

    # --- Validate & print summary --------------------------------------------
    report = blockchain.validate
    log.call("validate", report.ok? ? "chain OK (#{blockchain.chain.size} blocks)" : "ISSUES: #{report.issues}")

    io.puts ""
    io.puts "=== Summary: feature × block-indices ==="
    feature_blocks.each { |k, v| io.puts "  #{k.ljust(12)} #{v.inspect}" }
    io.puts "Branches: #{blockchain.chain.branches.inspect}"

    Result.new(blockchain, feature_blocks)
  end

  private def self.setup_voters(log) : Array(TheGooch::Voter)
    voters = [] of TheGooch::Voter
    12.times do |i|
      v = TheGooch::Voter.new(id: "voter#{i + 1}", region: REGIONS[i % REGIONS.size])
      voters << v
    end
    # Rig: Bold-voting voters (1,3,5,6,9) all in "south" to demonstrate
    # concentrated-minority detection in round 1.
    [1, 3, 5, 6].each { |i| voters[i].region = "south" }
    # voter 9 is already "south" by default (REGIONS[9 % 4] == "south")
    log.call("setup", "12 voters created, regions=#{voters.map(&.region).tally}")
    voters
  end

  private def self.cast_first_round(voters)
    votes = [] of TheGooch::Vote
    openings = {} of String => TheGooch::Crypto::Pedersen::Opening
    # 5 Calm vs 5 Bold (tie) → raw margin 0 < 5% triggers minority + fork checks.
    # All Bold voters in "south" → HHI of losing side = 1.0.
    intensities = {
      0 => {"Calm", 0.7}, 1 => {"Bold", 0.3}, 2 => {"Calm", 0.6}, 3 => {"Bold", 0.3},
      4 => {"Calm", 0.5}, 5 => {"Bold", 0.3}, 6 => {"Bold", 0.3}, 7 => {"Calm", 0.4},
      8 => {"Calm", 0.3}, 9 => {"Bold", 0.3},
    }
    10.times do |i|
      cand, intensity = intensities[i]
      result = TheGooch::Features::Emotional.cast(voters[i], cand, intensity)
      votes << result.vote
      openings[voters[i].id] = result.opening
    end
    {votes, openings}
  end

  private def self.cast_second_round(voters)
    votes = [] of TheGooch::Vote
    openings = {} of String => TheGooch::Crypto::Pedersen::Opening
    # Re-credit voters for the deliberated re-run.
    voters.each { |v| v.credits = TheGooch::Config::VOICE_CREDIT_BUDGET }
    # Voter 6 switches Bold→Calm post-deliberation. Result: 6 Calm vs 4 Bold,
    # raw margin = 0.2 (above minority threshold), intensity_gap stays small
    # (close to 0.01) → forking still triggers, minority does not.
    intensities = {
      0 => {"Calm", 0.6}, 1 => {"Bold", 0.4}, 2 => {"Calm", 0.5}, 3 => {"Bold", 0.4},
      4 => {"Calm", 0.5}, 5 => {"Bold", 0.5}, 6 => {"Calm", 0.4}, 7 => {"Calm", 0.4},
      8 => {"Calm", 0.4}, 9 => {"Bold", 0.5},
    }
    10.times do |i|
      cand, intensity = intensities[i]
      result = TheGooch::Features::Emotional.cast(voters[i], cand, intensity)
      votes << result.vote
      openings[voters[i].id] = result.opening
    end
    {votes, openings}
  end

  private def self.open_posthumous(sealed_tl, sealed_oracle, attest_msg, voters, votes, log) : Array(String)
    opened_ids = [] of String

    log.call("posthumous", "solving time-lock puzzle (T=#{TheGooch::Config::TIMELOCK_SPEC_T} squarings)")
    plaintext = sealed_tl.opens_with_timelock_solve
    if plaintext
      votes << TheGooch::Features::Posthumous.materialize(sealed_tl).as(TheGooch::Vote)
      opened_ids << sealed_tl.id
      log.call("posthumous", "time-lock opened: #{String.new(plaintext)}")
    end

    log.call("posthumous", "collecting 3 oracle attestations (of 5)")
    oracle = sealed_oracle.trigger.as(TheGooch::Features::Posthumous::OracleTrigger)
    shares = oracle.dealing.shares.first(3)
    attestation = TheGooch::Crypto::ThresholdSig.attest(attest_msg, shares, oracle.dealing.public_key)
    if sealed_oracle.opens_with_oracle?([attestation])
      votes << TheGooch::Features::Posthumous.materialize(sealed_oracle).as(TheGooch::Vote)
      opened_ids << sealed_oracle.id
      log.call("posthumous", "oracle trigger fired")
    end

    opened_ids
  end

  private def self.commit_election(blockchain, votes, opened_ids, branch, log, feature_blocks) : TheGooch::Block
    votes_json = votes.map(&.to_json)
    leaves = votes_json
    merkle_root = TheGooch::Merkle.root(leaves)
    body = TheGooch::BlockBody::Election.new(votes_json, opened_ids)
    blk = blockchain.append_block("election", body.to_json, merkle_root, [] of String, branch)
    feature_blocks["emotional"] << blk.index unless feature_blocks["emotional"].includes?(blk.index)
    feature_blocks["posthumous"] << blk.index if opened_ids.any?
    log.call("election", "committed block #{blk.index} (#{votes.size} votes, #{opened_ids.size} opened seals)")
    blk
  end
end
