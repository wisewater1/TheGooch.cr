require "../spec_helper"

describe TheGooch::Blockchain do
  it "starts with a single genesis block" do
    bc = TheGooch::Blockchain.new
    bc.chain.size.should eq(1)
    bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.body_kind.should eq("genesis")
  end

  it "appends and validates" do
    bc = TheGooch::Blockchain.new
    body = TheGooch::BlockBody::Election.new([] of String, [] of String)
    bc.append_block("election", body.to_json, "", [] of String, TheGooch::Chain::MAIN_BRANCH)
    bc.validate.ok?.should be_true
  end

  it "detects a tampered block hash" do
    bc = TheGooch::Blockchain.new
    body = TheGooch::BlockBody::Election.new([] of String, [] of String)
    blk = bc.append_block("election", body.to_json, "", [] of String, TheGooch::Chain::MAIN_BRANCH)
    blk.body_json = "tampered!"
    bc.validate.ok?.should be_false
  end
end
