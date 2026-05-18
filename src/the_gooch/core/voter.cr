require "../config"
require "../crypto/keypair"

class TheGooch::Voter
  getter id : String
  getter keypair : TheGooch::KeyPair
  property credits : UInt32
  property region : String

  def initialize(@id : String, @keypair : TheGooch::KeyPair = TheGooch::KeyPair.new,
                 @credits : UInt32 = TheGooch::Config::VOICE_CREDIT_BUDGET,
                 @region : String = "unset")
  end

  def spend(amount : UInt32)
    raise ArgumentError.new("insufficient voice credits: have #{@credits}, need #{amount}") if amount > @credits
    @credits -= amount
  end

  def public_key
    @keypair.public_key
  end
end
