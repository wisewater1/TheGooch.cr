require "../config"

# Forking Democracy — pure computation only.
# Blockchain mutation (fork!, reconcile) lives in
# TheGooch::Blockchain::Handlers::ForkingHandler.
module TheGooch::Features::Forking
  alias Config = TheGooch::Config

  def self.should_fork?(raw_margin : Float64, intensity_gap : Float64) : Bool
    raw_margin < Config::FORK_MARGIN_THRESHOLD || intensity_gap < Config::INTENSITY_GAP_THRESHOLD
  end
end
