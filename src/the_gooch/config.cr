module TheGooch::Config
  VOICE_CREDIT_BUDGET     =     100_u32
  INTENSITY_SCALE         =      10_u32 # 0..1 intensity discretized to 0..10
  # Quadratic cost: intensity_int² ranges 0..100, fits within budget per vote.
  FORK_MARGIN_THRESHOLD   =       0.05
  INTENSITY_GAP_THRESHOLD =       0.10
  MINORITY_CONCENTRATION  =       0.70
  MINORITY_MARGIN_TRIGGER =       0.05
  DECAY_LAMBDA            =       1e-8
  DECAY_EXPIRY_WEIGHT     =       0.10
  TIMELOCK_DEMO_T         = 200_000_u64
  TIMELOCK_SPEC_T         =   1_000_u64
  THRESHOLD_M             =       3
  THRESHOLD_N             =       5

  RECONCILIATION_WINDOW_SEC =  60
  LEGITIMACY_WINDOW_SEC     =  30

  PEDERSEN_BITS = 4 # range proofs for 0..15 (intensity * scale=10 maxes at 10)
end
