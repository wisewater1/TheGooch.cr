require "../spec_helper"

describe TheGooch::Crypto::TimeLock do
  it "round-trips with a tiny T" do
    plaintext = "vote:Calm".to_slice
    puzzle = TheGooch::Crypto::TimeLock.seal(plaintext, TheGooch::Config::TIMELOCK_SPEC_T)
    recovered = TheGooch::Crypto::TimeLock.solve(puzzle)
    String.new(recovered).should eq("vote:Calm")
  end

  it "tampered ciphertext fails to decrypt to the original" do
    plaintext = "vote:Bold".to_slice
    puzzle = TheGooch::Crypto::TimeLock.seal(plaintext, TheGooch::Config::TIMELOCK_SPEC_T)
    bytes = puzzle.ciphertext_hex.hexbytes
    bytes[0] ^= 0xff_u8
    tampered = TheGooch::Crypto::TimeLock::Puzzle.new(puzzle.n, puzzle.t, puzzle.a, bytes.hexstring)
    String.new(TheGooch::Crypto::TimeLock.solve(tampered)).should_not eq("vote:Bold")
  end
end
