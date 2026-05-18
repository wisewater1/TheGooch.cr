require "./the_gooch"
require "./the_gooch/web/server"

module TheGooch::CLI
  USAGE = <<-USAGE
  the_gooch — research-grade blockchain voting demo

  Usage:
    the_gooch demo [--time-skew=SECONDS]
    the_gooch validate
    the_gooch web [--port=PORT]
    the_gooch version

  USAGE

  def self.run(argv : Array(String))
    ::Log.setup(:info, ::Log::IOBackend.new(STDERR, formatter: ::Log::ShortFormat))

    case argv.first?
    when "demo"
      time_skew = parse_skew(argv)
      TheGooch::Demo.run(STDOUT, time_skew)
    when "validate"
      result = TheGooch::Demo.run(IO::Memory.new, 1.0e9)
      report = result.blockchain.validate
      if report.ok?
        puts "OK — #{result.blockchain.chain.size} blocks; branches=#{result.blockchain.chain.branches}"
        exit 0
      else
        puts "FAIL: #{report.issues.join("; ")}"
        exit 1
      end
    when "web"
      port = parse_port(argv)
      TheGooch::Web.run(port)
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
end

TheGooch::CLI.run(ARGV)
