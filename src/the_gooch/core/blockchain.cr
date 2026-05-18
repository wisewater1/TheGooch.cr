require "./block"
require "./block_store"
require "./chain"
require "./vote"

# Top-level facade. Mutating methods are protected by a single Mutex; we run
# single-threaded fibers (do NOT enable -Dpreview_mt for this shard).
class TheGooch::Blockchain
  getter chain : TheGooch::Chain
  getter store : TheGooch::BlockStore::Base
  @mutex : Mutex
  @last_index : Int32

  def initialize(@store : TheGooch::BlockStore::Base = TheGooch::BlockStore::Null.new)
    @chain = TheGooch::Chain.new
    @mutex = Mutex.new
    @last_index = -1
    existing = @store.load
    if existing.empty?
      seed_genesis
    else
      restore(existing)
    end
  end

  private def seed_genesis
    body = TheGooch::BlockBody::Genesis.new
    append_block("genesis", body.to_json, "", Array(String).new, TheGooch::Chain::MAIN_BRANCH)
  end

  private def restore(blocks : Array(TheGooch::Block))
    blocks.sort_by(&.index).each do |b|
      @chain.add(b)
      @last_index = b.index if b.index > @last_index
    end
    TheGooch::Log.info { "block.restore count=#{blocks.size}" }
  end

  def append_block(body_kind : String, body_json : String, merkle_root : String,
                   prev_hashes : Array(String), branch_id : String) : TheGooch::Block
    @mutex.synchronize do
      @last_index += 1
      prev = prev_hashes
      if prev.empty?
        head = @chain.head_of(branch_id) || @chain.head_of(TheGooch::Chain::MAIN_BRANCH)
        prev = head ? [head.hash] : [] of String
      end
      block = TheGooch::Block.new(
        index: @last_index,
        timestamp_ms: Time.utc.to_unix_ms,
        prev_hashes: prev,
        body_kind: body_kind,
        body_json: body_json,
        merkle_root: merkle_root,
        branch_id: branch_id
      )
      @chain.add(block)
      @store.append(block)
      TheGooch::Log.info { "block.append kind=#{body_kind} idx=#{block.index} branch=#{branch_id} hash=#{block.hash[0, 12]}" }
      block
    end
  end

  # Accept a pre-built block received from a peer. Returns false if the block
  # is already known or fails hash verification.
  def ingest(block : TheGooch::Block) : Bool
    @mutex.synchronize do
      return false if @chain.blocks.has_key?(block.hash)
      return false unless block.valid_hash?
      @chain.add(block)
      @store.append(block)
      @last_index = block.index if block.index > @last_index
      TheGooch::Log.info { "block.ingest idx=#{block.index} hash=#{block.hash[0, 12]}" }
      true
    end
  end

  def close
    @store.close
  end

  struct ValidationReport
    getter ok : Bool
    getter issues : Array(String)

    def initialize(@ok, @issues)
    end

    def ok? : Bool
      @ok
    end
  end

  def validate : ValidationReport
    issues = [] of String
    @chain.each do |block|
      issues << "bad hash on block #{block.index}" unless block.valid_hash?
      block.prev_hashes.each do |p|
        next if p.empty?
        unless @chain.blocks.has_key?(p)
          issues << "block #{block.index} references unknown parent #{p[0, 8]}"
        end
      end
    end
    ValidationReport.new(issues.empty?, issues)
  end
end
