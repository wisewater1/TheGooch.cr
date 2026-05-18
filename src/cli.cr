require "./the_gooch"
require "./the_gooch/web/server"

module TheGooch::CLI
  USAGE = <<-USAGE
  the_gooch — research-grade blockchain voting demo

  Usage:
    the_gooch demo [--time-skew=SECONDS] [--persist=PATH]
    the_gooch validate [--persist=PATH]
    the_gooch web  [--port=PORT] [--persist=PATH]
    the_gooch node --port=PORT [--peers=HOST:PORT,...] [--persist=PATH]
    the_gooch version

  USAGE

  def self.run(argv : Array(String))
    ::Log.setup(:info, ::Log::IOBackend.new(STDERR, formatter: ::Log::ShortFormat))

    case argv.first?
    when "demo"
      time_skew = parse_skew(argv)
      store = build_store(argv)
      TheGooch::Demo.run(STDOUT, time_skew, store)
      store.close
    when "validate"
      store = build_store(argv)
      result = TheGooch::Demo.run(IO::Memory.new, 1.0e9, store)
      report = result.blockchain.validate
      store.close
      if report.ok?
        puts "OK — #{result.blockchain.chain.size} blocks; branches=#{result.blockchain.chain.branches}"
        exit 0
      else
        puts "FAIL: #{report.issues.join("; ")}"
        exit 1
      end
    when "web"
      port = parse_port(argv)
      store = build_store(argv)
      TheGooch::Web.run(port, store)
    when "node"
      port = parse_port(argv)
      store = build_store(argv)
      blockchain = TheGooch::Blockchain.new(store)
      node = TheGooch::Net::GossipNode.new(blockchain, port)
      node.start
      parse_peers(argv).each { |h, p| node.connect(h, p) }
      puts "Gossip node #{node.node_id} listening on port #{port}. Press Ctrl-C to stop."
      sleep
    when "version"
      puts TheGooch::VERSION
    else
      puts USAGE
      exit argv.empty? ? 0 : 1
    end
  end

  private def self.parse_skew(argv) : Float64
    argv.each do |a|
      if a.starts_with?("--time-skew=")
        return a.split("=", 2)[1].to_f
      end
    end
    1.0e9
  end

  private def self.parse_port(argv) : Int32
    argv.each do |a|
      if a.starts_with?("--port=")
        return a.split("=", 2)[1].to_i
      end
    end
    3000
  end

  private def self.parse_peers(argv) : Array(Tuple(String, Int32))
    argv.each do |a|
      if a.starts_with?("--peers=")
        return a.split("=", 2)[1].split(",").map do |addr|
          parts = addr.strip.split(":")
          {parts[0], parts[1].to_i}
        end
      end
    end
    [] of Tuple(String, Int32)
  end

  private def self.build_store(argv) : TheGooch::BlockStore::Base
    argv.each do |a|
      if a.starts_with?("--persist=")
        return TheGooch::BlockStore::Jsonl.new(a.split("=", 2)[1])
      end
    end
    TheGooch::BlockStore::Null.new
  end
end

TheGooch::CLI.run(ARGV)
