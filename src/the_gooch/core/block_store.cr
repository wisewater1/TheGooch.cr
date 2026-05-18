require "./block"

# Persistence layer for a Blockchain. Stores one Block per line as JSON
# (append-only). On startup, the Blockchain replays the file to rebuild the
# in-memory DAG. No deletes, no compaction — research scope.
module TheGooch::BlockStore
  abstract class Base
    abstract def append(block : TheGooch::Block) : Nil
    abstract def load : Array(TheGooch::Block)

    def close
    end
  end

  # In-memory no-op store (default / pre-persistence behavior).
  class Null < Base
    def append(block : TheGooch::Block) : Nil
    end

    def load : Array(TheGooch::Block)
      [] of TheGooch::Block
    end
  end

  # Append-only JSON-Lines store.
  class Jsonl < Base
    @path : String
    @io : File?

    def initialize(@path : String)
      Dir.mkdir_p(File.dirname(@path)) unless File.dirname(@path) == "." || Dir.exists?(File.dirname(@path))
    end

    def append(block : TheGooch::Block) : Nil
      io = (@io ||= File.open(@path, "a"))
      io.puts(block.to_json)
      io.flush
    end

    def load : Array(TheGooch::Block)
      return [] of TheGooch::Block unless File.exists?(@path)
      blocks = [] of TheGooch::Block
      File.open(@path, "r") do |f|
        f.each_line do |line|
          next if line.strip.empty?
          blocks << TheGooch::Block.from_json(line)
        end
      end
      blocks
    end

    def close
      @io.try &.close
      @io = nil
    end
  end
end
