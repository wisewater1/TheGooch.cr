require "../spec_helper"

describe TheGooch::Crypto::ThresholdSig do
  it "M-of-N attestors produce verifiable signature" do
    dealing = TheGooch::Crypto::ThresholdSig.deal(3, 5)
    att = TheGooch::Crypto::ThresholdSig.attest("hello", dealing.shares.first(3), dealing.public_key)
    TheGooch::Crypto::ThresholdSig.verify("hello", att).should be_true
  end

  it "M-1 attestors fail" do
    dealing = TheGooch::Crypto::ThresholdSig.deal(3, 5)
    expect_raises(Exception) do
      TheGooch::Crypto::ThresholdSig.attest("hello", dealing.shares.first(2), dealing.public_key)
    end
  end
end
