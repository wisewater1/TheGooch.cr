# Hand-rolled libgmp FFI bindings for the time-lock puzzle's hot loop.
# Crystal's stdlib `big` already binds libgmp but we keep our own minimal
# surface so the timelock module is self-contained and easy to audit.
#
# Fallback: if compiled with `-Dno_gmp`, the timelock falls back to Crystal's
# BigInt (slower but no native dependency).

{% unless flag?(:no_gmp) %}
  @[Link("gmp")]
  lib TheGooch::Crypto::LibGMP
    struct MpzStruct
      alloc : Int32
      size : Int32
      d : LibC::ULong*
    end

    alias Mpz = MpzStruct

    fun init = __gmpz_init(rop : Mpz*)
    fun clear = __gmpz_clear(rop : Mpz*)
    fun set_str = __gmpz_set_str(rop : Mpz*, str : LibC::Char*, base : Int32) : Int32
    fun get_str = __gmpz_get_str(rop : LibC::Char*, base : Int32, op : Mpz*) : LibC::Char*
    fun sizeinbase = __gmpz_sizeinbase(op : Mpz*, base : Int32) : LibC::SizeT
    fun mul = __gmpz_mul(rop : Mpz*, op1 : Mpz*, op2 : Mpz*)
    fun mod = __gmpz_mod(rop : Mpz*, op : Mpz*, mod : Mpz*)
    fun powm = __gmpz_powm(rop : Mpz*, base : Mpz*, exp : Mpz*, mod : Mpz*)
    fun cmp = __gmpz_cmp(op1 : Mpz*, op2 : Mpz*) : Int32
  end

  # RAII wrapper around an mpz_t. Always heap-allocated (one struct in a
  # StaticArray) so the pointer survives moves.
  class TheGooch::Crypto::Mpz
    @mpz : StaticArray(LibGMP::MpzStruct, 1)

    def initialize
      @mpz = StaticArray(LibGMP::MpzStruct, 1).new(LibGMP::MpzStruct.new)
      LibGMP.init(self.to_unsafe)
    end

    def self.from_s(s : String, base : Int32 = 10) : Mpz
      m = new
      LibGMP.set_str(m.to_unsafe, s.to_unsafe, base)
      m
    end

    def self.from_bigint(b : BigInt) : Mpz
      from_s(b.to_s(16), 16)
    end

    def to_unsafe
      @mpz.to_unsafe
    end

    def to_s(base : Int32 = 10) : String
      size = LibGMP.sizeinbase(self.to_unsafe, base) + 2
      buf = Bytes.new(size)
      LibGMP.get_str(buf.to_unsafe.as(LibC::Char*), base, self.to_unsafe)
      String.new(buf.to_unsafe.as(LibC::Char*))
    end

    def to_bigint : BigInt
      BigInt.new(to_s(16), 16)
    end

    def finalize
      LibGMP.clear(self.to_unsafe)
    end
  end
{% else %}
  class TheGooch::Crypto::Mpz
    @value : BigInt

    def initialize(@value : BigInt = BigInt.new(0))
    end

    def self.from_s(s : String, base : Int32 = 10) : Mpz
      new(BigInt.new(s, base))
    end

    def self.from_bigint(b : BigInt) : Mpz
      new(b)
    end

    def to_bigint : BigInt
      @value
    end

    getter value
  end
{% end %}
