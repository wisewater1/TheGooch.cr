require "json"

module TheGooch::Net
  # Wire message exchanged over a TCP connection. Line-delimited JSON.
  struct Message
    include JSON::Serializable

    property kind : String
    property node_id : String?
    property block_hash : String?
    property block_index : Int32?
    property block_json : String?

    def initialize(@kind, @node_id = nil, @block_hash = nil,
                   @block_index = nil, @block_json = nil)
    end

    def self.handshake(node_id : String, tip_hash : String) : Message
      new("handshake", node_id: node_id, block_hash: tip_hash)
    end

    def self.announce(block_hash : String, block_index : Int32) : Message
      new("announce", block_hash: block_hash, block_index: block_index)
    end

    def self.request_block(block_hash : String) : Message
      new("request_block", block_hash: block_hash)
    end

    def self.block_msg(block_json : String) : Message
      new("block", block_json: block_json)
    end

    def self.ping : Message
      new("ping")
    end

    def self.pong : Message
      new("pong")
    end
  end
end
