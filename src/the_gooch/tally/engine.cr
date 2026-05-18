require "../core/blockchain"
require "../core/vote"
require "../crypto/pedersen"
require "../features/emotional"

# Tally engine. Produces a Tally body summarizing raw + weighted results,
# margins, and intensity gap. The Blockchain caller decides whether to
# materialize the Tally block immediately or defer it (e.g., when the
# minority module triggers a Deliberation).
module TheGooch::Tally
  alias Pedersen = TheGooch::Crypto::Pedersen
  alias Emotional = TheGooch::Features::Emotional

  struct Outcome
    getter per_candidate_raw : Hash(String, Int32)
    getter per_candidate_weighted : Hash(String, Float64)
    getter winner : String
    getter raw_margin : Float64
    getter weighted_margin : Float64
    getter intensity_gap : Float64

    def initialize(@per_candidate_raw, @per_candidate_weighted, @winner,
                   @raw_margin, @weighted_margin, @intensity_gap)
    end

    def to_body(election_block_hash : String) : TheGooch::BlockBody::Tally
      TheGooch::BlockBody::Tally.new(
        election_block_hash, @per_candidate_raw, @per_candidate_weighted,
        @winner, @raw_margin, @weighted_margin, @intensity_gap
      )
    end
  end

  def self.compute(votes : Array(TheGooch::Vote),
                   openings : Hash(String, Pedersen::Opening)) : Outcome
    raw = Hash(String, Int32).new(0)
    weighted = Hash(String, Float64).new(0.0)
    votes.each do |v|
      raw[v.candidate] += 1
      case v
      when TheGooch::EmotionalVote
        opening = openings[v.voter_id]?
        if opening && Pedersen.open(v.intensity_commitment, opening)
          weighted[v.candidate] += opening.value.to_f / TheGooch::Config::INTENSITY_SCALE
        else
          weighted[v.candidate] += 1.0 # fallback: vote-but-no-intensity counts as 1.0
        end
      else
        weighted[v.candidate] += 1.0
      end
    end

    total_raw = raw.values.sum
    total_weighted = weighted.values.sum
    sorted_raw = raw.to_a.sort_by { |(_, c)| -c }
    sorted_w = weighted.to_a.sort_by { |(_, c)| -c }

    winner = sorted_w.first[0]
    raw_margin = if total_raw > 0 && sorted_raw.size > 1
                   (sorted_raw[0][1] - sorted_raw[1][1]).to_f / total_raw
                 else
                   1.0
                 end
    weighted_margin = if total_weighted > 0 && sorted_w.size > 1
                        (sorted_w[0][1] - sorted_w[1][1]) / total_weighted
                      else
                        1.0
                      end
    intensity_gap = if sorted_w.size > 1 && sorted_raw.size > 1
                      # difference between weighted-share and raw-share for the winner
                      ws = sorted_w[0][1] / total_weighted
                      rs = sorted_raw[0][1].to_f / total_raw
                      (ws - rs).abs
                    else
                      0.0
                    end

    Outcome.new(raw, weighted, winner, raw_margin, weighted_margin, intensity_gap)
  end
end
