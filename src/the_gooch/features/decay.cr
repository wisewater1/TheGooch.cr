require "math"
require "../config"

# Vote Decay — pure computation only.
# Blockchain mutation (scan, ratify) lives in
# TheGooch::Blockchain::Handlers::DecayHandler.
#
# Each finalized outcome carries a created-at timestamp; effective weight is
# original_weight * exp(-λ · elapsed_seconds). Ratification (re-affirmation
# by original voters) resets the clock. When effective_weight falls below
# DECAY_EXPIRY_WEIGHT × original, an Expiry block is emitted by DecayHandler.
module TheGooch::Features::Decay
  alias Config = TheGooch::Config

  def self.effective_weight(original : Float64, elapsed_seconds : Float64,
                            lambda_ : Float64 = Config::DECAY_LAMBDA) : Float64
    original * Math.exp(-lambda_ * elapsed_seconds)
  end

  def self.expired?(original : Float64, effective : Float64,
                    threshold : Float64 = Config::DECAY_EXPIRY_WEIGHT) : Bool
    effective < original * threshold
  end
end
