require "../config"
require "../core/blockchain"
require "../core/vote"

# Adversarial Minority Protection.
#
# When the losing side's voters are geographically/demographically
# concentrated AND the overall margin is narrow, finalization is deferred:
# a Deliberation block is appended in lieu of (or before) a Tally block.
#
# Concentration is the normalized Herfindahl-Hirschman Index over the
# losing-side voter region distribution: HHI ∈ [1/k, 1] where k is the
# number of regions represented.
module TheGooch::Features::Minority
  alias Config = TheGooch::Config

  struct Assessment
    getter trigger : Bool
    getter report : TheGooch::BlockBody::MinorityReport?

    def initialize(@trigger, @report)
    end
  end

  def self.compute_hhi(region_counts : Hash(String, Int32)) : Float64
    total = region_counts.values.sum
    return 0.0 if total == 0
    region_counts.values.sum { |c| (c.to_f / total) ** 2 }
  end

  def self.dominant_region(region_counts : Hash(String, Int32)) : String
    region_counts.max_by? { |(_, c)| c }.try(&.[0]) || "unknown"
  end

  def self.assess(votes : Array(TheGooch::Vote), per_candidate_raw : Hash(String, Int32),
                  margin : Float64) : Assessment
    return Assessment.new(false, nil) if per_candidate_raw.size < 2
    sorted = per_candidate_raw.to_a.sort_by { |(_, c)| -c }
    losing = sorted.last[0]

    losing_voters = votes.select { |v| v.candidate == losing }
    region_counts = Hash(String, Int32).new(0)
    losing_voters.each { |v| region_counts[v.region || "unknown"] += 1 }

    hhi = compute_hhi(region_counts)
    return Assessment.new(false, nil) unless hhi > Config::MINORITY_CONCENTRATION && margin < Config::MINORITY_MARGIN_TRIGGER

    report = TheGooch::BlockBody::MinorityReport.new(
      losing_side: losing,
      hhi: hhi,
      margin: margin,
      dominant_region: dominant_region(region_counts)
    )
    Assessment.new(true, report)
  end
end
