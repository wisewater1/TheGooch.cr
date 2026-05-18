require "./block"

# A DAG of blocks keyed by hash, supporting multiple heads (one per branch).
# Forking creates a new head; reconciliation creates a node with two parents.
class TheGooch::Chain
  getter blocks : Hash(String, TheGooch::Block)
  getter heads : Hash(String, String) # branch_id => block hash
  getter children : Hash(String, Array(String))

  MAIN_BRANCH = "main"

  def initialize
    @blocks = {} of String => TheGooch::Block
    @heads = {} of String => String
    @children = Hash(String, Array(String)).new { |h, k| h[k] = [] of String }
  end

  def add(block : TheGooch::Block)
    @blocks[block.hash] = block
    block.prev_hashes.each { |p| @children[p] << block.hash }
    @heads[block.branch_id] = block.hash
  end

  def head_of(branch_id : String = MAIN_BRANCH) : TheGooch::Block?
    h = @heads[branch_id]?
    h ? @blocks[h] : nil
  end

  def branches : Array(String)
    @heads.keys
  end

  def walk_from(hash : String) : Array(TheGooch::Block)
    out = [] of TheGooch::Block
    visited = Set(String).new
    queue = [hash]
    while h = queue.shift?
      next if visited.includes?(h)
      visited << h
      blk = @blocks[h]?
      next unless blk
      out << blk
      blk.prev_hashes.each { |p| queue << p }
    end
    out
  end

  def each(&)
    @blocks.each_value { |b| yield b }
  end

  def size
    @blocks.size
  end
end
