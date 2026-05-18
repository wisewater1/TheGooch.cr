require "digest/sha256"

module TheGooch::Crypto
  def self.h(domain : Symbol | String, *parts) : String
    digest = Digest::SHA256.new
    digest.update(domain.to_s)
    digest.update("|")
    parts.each do |p|
      digest.update(p.to_s)
      digest.update("|")
    end
    digest.final.hexstring
  end

  def self.h_bytes(domain : Symbol | String, *parts) : Bytes
    digest = Digest::SHA256.new
    digest.update(domain.to_s)
    digest.update("|")
    parts.each do |p|
      digest.update(p.to_s)
      digest.update("|")
    end
    digest.final
  end
end
