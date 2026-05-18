require "../spec_helper"

describe TheGooch::KeyPair do
  it "signs and verifies its own messages" do
    kp = TheGooch::KeyPair.new
    sig = kp.sign("hello")
    TheGooch::KeyPair.verify(kp.public_key, "hello", sig).should be_true
  end

  it "rejects a tampered message" do
    kp = TheGooch::KeyPair.new
    sig = kp.sign("hello")
    TheGooch::KeyPair.verify(kp.public_key, "hallo", sig).should be_false
  end

  it "rejects another voter's pubkey" do
    a = TheGooch::KeyPair.new
    b = TheGooch::KeyPair.new
    sig = a.sign("x")
    TheGooch::KeyPair.verify(b.public_key, "x", sig).should be_false
  end
end
