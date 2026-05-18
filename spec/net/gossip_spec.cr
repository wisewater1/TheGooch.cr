require "../spec_helper"

# Helpers ------------------------------------------------------------------ #

private def fresh_blockchain
  TheGooch::Blockchain.new(TheGooch::BlockStore::Null.new)
end

private def fresh_node(port : Int32) : TheGooch::Net::GossipNode
  node = TheGooch::Net::GossipNode.new(fresh_blockchain, port)
  node.start
  node
end

# Poll until the condition is true or the deadline passes (milliseconds).
private def wait_until(ms : Int32 = 500, &cond : -> Bool) : Bool
  deadline = Time.monotonic + ms.milliseconds
  while Time.monotonic < deadline
    return true if cond.call
    Fiber.yield
    sleep 10.milliseconds
  end
  false
end

# Unique ports to avoid collisions between concurrent spec runs.
GOSSIP_PORT_BASE = 19_600

# ------------------------------------------------------------------ specs -- #

describe TheGooch::Net::GossipNode do
  describe "Message serialization" do
    it "round-trips handshake" do
      m = TheGooch::Net::Message.handshake("node1", "abc123")
      r = TheGooch::Net::Message.from_json(m.to_json)
      r.kind.should eq("handshake")
      r.node_id.should eq("node1")
      r.block_hash.should eq("abc123")
    end

    it "round-trips announce" do
      m = TheGooch::Net::Message.announce("deadbeef", 42)
      r = TheGooch::Net::Message.from_json(m.to_json)
      r.kind.should eq("announce")
      r.block_hash.should eq("deadbeef")
      r.block_index.should eq(42)
    end

    it "round-trips request_block" do
      m = TheGooch::Net::Message.request_block("cafebabe")
      r = TheGooch::Net::Message.from_json(m.to_json)
      r.kind.should eq("request_block")
      r.block_hash.should eq("cafebabe")
    end

    it "round-trips block_msg" do
      m = TheGooch::Net::Message.block_msg("{\"index\":1}")
      r = TheGooch::Net::Message.from_json(m.to_json)
      r.kind.should eq("block")
      r.block_json.should eq("{\"index\":1}")
    end

    it "round-trips ping/pong" do
      TheGooch::Net::Message.from_json(TheGooch::Net::Message.ping.to_json).kind.should eq("ping")
      TheGooch::Net::Message.from_json(TheGooch::Net::Message.pong.to_json).kind.should eq("pong")
    end
  end

  describe "node lifecycle" do
    it "starts and stops cleanly" do
      node = fresh_node(GOSSIP_PORT_BASE)
      node.peer_count.should eq(0)
      node.stop
    end

    it "assigns a node_id automatically" do
      node = TheGooch::Net::GossipNode.new(fresh_blockchain, GOSSIP_PORT_BASE + 1)
      node.node_id.should_not be_empty
      node.stop
    end

    it "accepts a custom node_id" do
      node = TheGooch::Net::GossipNode.new(fresh_blockchain, GOSSIP_PORT_BASE + 2, node_id: "peer-alpha")
      node.node_id.should eq("peer-alpha")
      node.stop
    end
  end

  describe "two-node gossip" do
    it "connects peer A -> peer B and counts the peer" do
      a = fresh_node(GOSSIP_PORT_BASE + 10)
      b = fresh_node(GOSSIP_PORT_BASE + 11)

      a.connect("127.0.0.1", GOSSIP_PORT_BASE + 11).should be_true
      wait_until { b.peer_count >= 1 }
      b.peer_count.should be >= 1

      a.stop
      b.stop
    end

    it "propagates a block from A to B" do
      bc_a = fresh_blockchain
      bc_b = fresh_blockchain

      a = TheGooch::Net::GossipNode.new(bc_a, GOSSIP_PORT_BASE + 20)
      b = TheGooch::Net::GossipNode.new(bc_b, GOSSIP_PORT_BASE + 21)
      a.start
      b.start

      a.connect("127.0.0.1", GOSSIP_PORT_BASE + 21)
      sleep 20.milliseconds # let handshake complete

      body = TheGooch::BlockBody::Election.new([] of String, [] of String)
      blk = bc_a.append_block("election", body.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      a.broadcast_block(blk)

      propagated = wait_until(800) { bc_b.chain.blocks.has_key?(blk.hash) }
      propagated.should be_true
      bc_b.chain.blocks[blk.hash].body_kind.should eq("election")

      a.stop
      b.stop
    end

    it "does not duplicate a block already known by the receiver" do
      bc_a = fresh_blockchain
      bc_b = fresh_blockchain

      a = TheGooch::Net::GossipNode.new(bc_a, GOSSIP_PORT_BASE + 30)
      b = TheGooch::Net::GossipNode.new(bc_b, GOSSIP_PORT_BASE + 31)
      a.start
      b.start

      a.connect("127.0.0.1", GOSSIP_PORT_BASE + 31)
      sleep 20.milliseconds

      body = TheGooch::BlockBody::Election.new([] of String, [] of String)
      blk = bc_a.append_block("election", body.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      a.broadcast_block(blk)
      wait_until(800) { bc_b.chain.blocks.has_key?(blk.hash) }

      size_before = bc_b.chain.size
      # Send the same announce again — should be a no-op.
      a.broadcast_block(blk)
      sleep 100.milliseconds
      bc_b.chain.size.should eq(size_before)

      a.stop
      b.stop
    end

    it "rejects a block with an invalid hash" do
      bc_a = fresh_blockchain
      bc_b = fresh_blockchain

      a = TheGooch::Net::GossipNode.new(bc_a, GOSSIP_PORT_BASE + 40)
      b = TheGooch::Net::GossipNode.new(bc_b, GOSSIP_PORT_BASE + 41)
      a.start
      b.start
      a.connect("127.0.0.1", GOSSIP_PORT_BASE + 41)
      sleep 20.milliseconds

      # Build a block but corrupt its hash field via JSON surgery.
      body = TheGooch::BlockBody::Election.new([] of String, [] of String)
      blk = bc_a.append_block("election", body.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      json = blk.to_json.gsub(blk.hash, "0" * 64)
      sock = TCPSocket.new("127.0.0.1", GOSSIP_PORT_BASE + 41)
      sock.puts(TheGooch::Net::Message.block_msg(json).to_json)
      sock.close
      sleep 80.milliseconds

      bc_b.chain.size.should eq(1) # only genesis

      a.stop
      b.stop
    end

    it "fires the on_block callback when a block arrives from the network" do
      bc_a = fresh_blockchain
      bc_b = fresh_blockchain
      received = Channel(TheGooch::Block).new(4)

      a = TheGooch::Net::GossipNode.new(bc_a, GOSSIP_PORT_BASE + 50)
      b = TheGooch::Net::GossipNode.new(bc_b, GOSSIP_PORT_BASE + 51)
      b.on_block { |blk| received.send(blk) }
      a.start
      b.start
      a.connect("127.0.0.1", GOSSIP_PORT_BASE + 51)
      sleep 20.milliseconds

      body = TheGooch::BlockBody::Election.new([] of String, [] of String)
      blk = bc_a.append_block("election", body.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
      a.broadcast_block(blk)

      got = nil
      select
      when got = received.receive
      when timeout(500.milliseconds)
      end
      got.should_not be_nil
      got.not_nil!.hash.should eq(blk.hash)

      a.stop
      b.stop
    end
  end

  describe "Blockchain#ingest" do
    it "adds a valid external block" do
      bc = fresh_blockchain
      genesis_hash = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      body = TheGooch::BlockBody::Election.new([] of String, [] of String)
      blk = TheGooch::Block.new(
        index: 1,
        timestamp_ms: Time.utc.to_unix_ms,
        prev_hashes: [genesis_hash],
        body_kind: "election",
        body_json: body.to_json,
        merkle_root: "",
        branch_id: TheGooch::Chain::MAIN_BRANCH
      )
      bc.ingest(blk).should be_true
      bc.chain.size.should eq(2)
    end

    it "rejects a duplicate ingest" do
      bc = fresh_blockchain
      genesis_hash = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      body = TheGooch::BlockBody::Election.new([] of String, [] of String)
      blk = TheGooch::Block.new(
        index: 1,
        timestamp_ms: Time.utc.to_unix_ms,
        prev_hashes: [genesis_hash],
        body_kind: "election",
        body_json: body.to_json,
        merkle_root: "",
        branch_id: TheGooch::Chain::MAIN_BRANCH
      )
      bc.ingest(blk).should be_true
      bc.ingest(blk).should be_false
      bc.chain.size.should eq(2)
    end

    it "rejects a block with a corrupted hash" do
      bc = fresh_blockchain
      genesis_hash = bc.chain.head_of(TheGooch::Chain::MAIN_BRANCH).not_nil!.hash
      body = TheGooch::BlockBody::Election.new([] of String, [] of String)
      good = TheGooch::Block.new(
        index: 1,
        timestamp_ms: Time.utc.to_unix_ms,
        prev_hashes: [genesis_hash],
        body_kind: "election",
        body_json: body.to_json,
        merkle_root: "",
        branch_id: TheGooch::Chain::MAIN_BRANCH
      )
      # Deserialise and re-serialise with a zeroed hash to simulate tampering.
      tampered = TheGooch::Block.from_json(good.to_json.gsub(good.hash, "0" * 64))
      bc.ingest(tampered).should be_false
      bc.chain.size.should eq(1)
    end
  end
end
