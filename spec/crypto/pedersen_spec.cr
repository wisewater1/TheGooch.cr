require "../spec_helper"

describe TheGooch::Crypto::Pedersen do
  it "opens an honest commitment" do
    c, o = TheGooch::Crypto::Pedersen.commit(BigInt.new(42))
    TheGooch::Crypto::Pedersen.open(c, o).should be_true
  end

  it "rejects a tampered opening" do
    c, o = TheGooch::Crypto::Pedersen.commit(BigInt.new(42))
    bad = TheGooch::Crypto::Pedersen::Opening.new(BigInt.new(43), o.blinding)
    TheGooch::Crypto::Pedersen.open(c, bad).should be_false
  end

  it "is additively homomorphic" do
    c1, o1 = TheGooch::Crypto::Pedersen.commit(BigInt.new(10))
    c2, o2 = TheGooch::Crypto::Pedersen.commit(BigInt.new(20))
    sum = TheGooch::Crypto::Pedersen.add(c1, c2)
    combined = TheGooch::Crypto::Pedersen::Opening.new(
      BigInt.new(30),
      (o1.blinding + o2.blinding) % TheGooch::Crypto::Group::Q
    )
    TheGooch::Crypto::Pedersen.open(sum, combined).should be_true
  end
end
