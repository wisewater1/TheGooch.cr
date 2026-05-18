require "socket"
require "./message"

# Minimal gossip overlay. Each GossipNode wraps a Blockchain and maintains
# a set of outbound+inbound TCP peer sockets. Protocol is line-delimited JSON.
#
# Message flow:
#   connect  →  handshake  →  peer sends back announce(tip)
#   local append_block  →  broadcast announce(hash, idx) to all peers
#   peer receives announce  →  if unseen, sends request_block(hash)
#   receiving request_block  →  reply with block(block_json)
#   receiving block  →  ingest into local chain, re-announce to others
#
# No authentication on block authorship at the gossip layer; the Blockchain
# validates hash integrity and the caller is responsible for signature checking.
module TheGooch::Net
  class GossipNode
    getter node_id : String
    getter port : Int32

    @blockchain : TheGooch::Blockchain
    @server : TCPServer?
    @peers : Array(TCPSocket)
    @peers_mutex : Mutex
    @seen : Set(String)
    @seen_mutex : Mutex
    @on_block : Proc(TheGooch::Block, Nil)?
    @running : Bool

    def initialize(@blockchain : TheGooch::Blockchain, @port : Int32,
                   node_id : String? = nil)
      @node_id = node_id || Random::Secure.hex(8)
      @peers = [] of TCPSocket
      @peers_mutex = Mutex.new
      @seen_mutex = Mutex.new
      @seen = Set(String).new
      @blockchain.chain.each { |b| @seen << b.hash }
      @running = false
    end

    # Register a callback invoked whenever a block is ingested from the network.
    def on_block(&block : TheGooch::Block -> Nil)
      @on_block = block
    end

    # Start the TCP listener in a background fiber. Non-blocking relative to the
    # caller — returns immediately.
    def start
      @running = true
      server = TCPServer.new("127.0.0.1", @port)
      @server = server
      TheGooch::Log.info { "gossip.listen port=#{@port} node=#{@node_id}" }
      spawn do
        while @running
          begin
            sock = server.accept?
            break unless sock
            spawn handle_peer(sock)
          rescue ex
            break unless @running
            TheGooch::Log.warn { "gossip.accept error=#{ex.message}" }
          end
        end
      end
    end

    # Dial a remote peer. Returns true on success, false on connection failure.
    def connect(host : String, remote_port : Int32) : Bool
      sock = TCPSocket.new(host, remote_port)
      register_peer(sock)
      send_msg(sock, Message.handshake(@node_id, tip_hash))
      spawn handle_peer(sock)
      TheGooch::Log.info { "gossip.connect host=#{host} port=#{remote_port}" }
      true
    rescue ex
      TheGooch::Log.warn { "gossip.connect_failed host=#{host} port=#{remote_port} error=#{ex.message}" }
      false
    end

    # Announce a block that was appended locally (call this after Blockchain#append_block).
    def broadcast_block(block : TheGooch::Block)
      mark_seen(block.hash)
      broadcast(Message.announce(block.hash, block.index))
    end

    def stop
      @running = false
      @server.try &.close
      @peers_mutex.synchronize do
        @peers.each { |s| s.close rescue nil }
        @peers.clear
      end
    end

    def peer_count : Int32
      @peers_mutex.synchronize { @peers.size }
    end

    private def tip_hash : String
      head = @blockchain.chain.head_of(TheGooch::Chain::MAIN_BRANCH)
      head ? head.hash : ""
    end

    private def register_peer(sock : TCPSocket)
      @peers_mutex.synchronize do
        @peers << sock unless @peers.includes?(sock)
      end
    end

    private def remove_peer(sock : TCPSocket)
      @peers_mutex.synchronize { @peers.delete(sock) }
      sock.close rescue nil
    end

    # Returns true only the first time a hash is seen (insert-once).
    private def mark_seen(hash : String) : Bool
      @seen_mutex.synchronize do
        return false if @seen.includes?(hash)
        @seen << hash
        true
      end
    end

    private def seen?(hash : String) : Bool
      @seen_mutex.synchronize { @seen.includes?(hash) }
    end

    private def broadcast(msg : Message)
      json = msg.to_json
      @peers_mutex.synchronize { @peers.dup }.each do |sock|
        sock.puts(json)
      rescue
        remove_peer(sock)
      end
    end

    private def send_msg(sock : TCPSocket, msg : Message)
      sock.puts(msg.to_json)
    end

    private def handle_peer(sock : TCPSocket)
      register_peer(sock)
      sock.each_line do |line|
        next if line.strip.empty?
        msg = Message.from_json(line)
        handle_message(sock, msg)
      end
    rescue ex
      TheGooch::Log.debug { "gossip.peer_disconnected error=#{ex.message}" }
    ensure
      remove_peer(sock)
    end

    private def handle_message(sock : TCPSocket, msg : Message)
      case msg.kind
      when "handshake"
        # Peer told us their tip; we reply with our own tip announce.
        send_msg(sock, Message.announce(tip_hash, @blockchain.chain.size - 1))
      when "announce"
        hash = msg.block_hash
        return unless hash
        return if seen?(hash)
        send_msg(sock, Message.request_block(hash))
      when "request_block"
        hash = msg.block_hash
        return unless hash
        block = @blockchain.chain.blocks[hash]?
        return unless block
        send_msg(sock, Message.block_msg(block.to_json))
      when "block"
        json = msg.block_json
        return unless json
        begin
          block = TheGooch::Block.from_json(json)
          ingest(block)
        rescue ex
          TheGooch::Log.warn { "gossip.bad_block error=#{ex.message}" }
        end
      when "ping"
        send_msg(sock, Message.pong)
      end
    end

    private def ingest(block : TheGooch::Block)
      return unless mark_seen(block.hash)
      return unless block.valid_hash?
      added = @blockchain.ingest(block)
      return unless added
      @on_block.try &.call(block)
      broadcast(Message.announce(block.hash, block.index))
      TheGooch::Log.info { "gossip.ingested hash=#{block.hash[0, 12]} idx=#{block.index}" }
    end
  end
end
