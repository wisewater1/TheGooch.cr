require "../spec_helper"

describe TheGooch::Crypto::Shamir do
  it "reconstructs from any k shares" do
    secret = BigInt.new("123456789012345678901234567890")
    shares = TheGooch::Crypto::Shamir.split(secret, 3, 5)
    [shares[0..2], shares[1..3], [shares[0], shares[2], shares[4]]].each do |subset|
      TheGooch::Crypto::Shamir.combine(subset).should eq(secret % TheGooch::Crypto::Group::Q)
    end
  end

  it "fails to reconstruct with k-1 shares" do
    secret = BigInt.new(987654321)
    shares = TheGooch::Crypto::Shamir.split(secret, 3, 5)
    TheGooch::Crypto::Shamir.combine(shares[0..1]).should_not eq(secret % TheGooch::Crypto::Group::Q)
  end
end
