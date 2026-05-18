require "../spec_helper"

private def tmp_path : String
  File.tempname("the_gooch_store", ".jsonl")
end

describe TheGooch::BlockStore::Jsonl do
  it "round-trips an empty file" do
    path = tmp_path
    store = TheGooch::BlockStore::Jsonl.new(path)
    store.load.should be_empty
    store.close
    File.delete?(path)
  end

  it "appends one block and reloads it" do
    path = tmp_path
    bc = TheGooch::Blockchain.new(TheGooch::BlockStore::Jsonl.new(path))
    body = TheGooch::BlockBody::Election.new([] of String, [] of String)
    bc.append_block("election", body.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
    bc.close

    reloaded = TheGooch::Blockchain.new(TheGooch::BlockStore::Jsonl.new(path))
    reloaded.chain.size.should eq(2) # genesis + election
    reloaded.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.body_kind.should eq("election")
    reloaded.close
    File.delete?(path)
  end

  it "preserves DAG branches across restart" do
    path = tmp_path
    bc = TheGooch::Blockchain.new(TheGooch::BlockStore::Jsonl.new(path))
    parent = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
    TheGooch::Blockchain::Handlers::ForkingHandler.new(bc).fork!(parent, "test")
    pre_branches = bc.chain.branches.sort
    pre_size = bc.chain.size
    bc.close

    reloaded = TheGooch::Blockchain.new(TheGooch::BlockStore::Jsonl.new(path))
    reloaded.chain.size.should eq(pre_size)
    reloaded.chain.branches.sort.should eq(pre_branches)
    reloaded.validate.ok?.should be_true
    reloaded.close
    File.delete?(path)
  end

  it "continues appending with the correct index after restart" do
    path = tmp_path
    bc = TheGooch::Blockchain.new(TheGooch::BlockStore::Jsonl.new(path))
    body = TheGooch::BlockBody::Election.new([] of String, [] of String)
    bc.append_block("election", body.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
    bc.close

    reloaded = TheGooch::Blockchain.new(TheGooch::BlockStore::Jsonl.new(path))
    next_block = reloaded.append_block("election", body.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
    next_block.index.should eq(2)
    reloaded.validate.ok?.should be_true
    reloaded.close
    File.delete?(path)
  end

  it "Null store leaves no persistence (default behavior unchanged)" do
    bc = TheGooch::Blockchain.new
    bc.chain.size.should eq(1)
    bc.store.should be_a(TheGooch::BlockStore::Null)
  end
end
