require "./spec_helper"
require "set"

describe "TheGooch end-to-end demo" do
  it "fires every feature and the chain validates" do
    result = TheGooch::Demo.run(IO::Memory.new, 1.0e9)
    bc = result.blockchain
    report = bc.validate
    report.ok?.should be_true

    kinds = bc.chain.blocks.values.map(&.body_kind).to_set
    expected = Set{"genesis", "election", "tally", "legitimacy",
                   "deliberation", "fork", "reconciliation",
                   "expiry", "ratification"}
    missing = expected - kinds
    missing.should be_empty

    bc.chain.branches.size.should be >= 1
  end
end
