require "../spec_helper"

describe TheGooch::Features::Decay do
  it "decays exponentially" do
    w0 = TheGooch::Features::Decay.effective_weight(1.0, 0.0)
    w1 = TheGooch::Features::Decay.effective_weight(1.0, 1.0e8)
    w0.should eq(1.0)
    w1.should be < w0
  end

  it "expires below threshold" do
    TheGooch::Features::Decay.expired?(1.0, 0.05).should be_true
    TheGooch::Features::Decay.expired?(1.0, 0.50).should be_false
  end
end
