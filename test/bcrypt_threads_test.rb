# Concurrent hashing: threads on separate OS workers each hash their own
# secret under their own fixed salt, many times over, and count the
# results that differ from the digest computed before any thread started.
# The C glue returns its result through a buffer, so a buffer shared by
# all threads lets one thread read another's digest (or a half-written
# one); each must see only its own. Salt generation runs concurrently
# too, and every salt must be well formed.
#
# With a single OS worker the threads take turns and nothing can race,
# so the workers are set before the first thread starts (Spinel reads
# SPINEL_WORKERS then).
ENV["SPINEL_WORKERS"] = "5"
require "bcrypt"

THREADS = 4
ROUNDS = 1500

salts = []
secrets = []
expected = []
i = 0
while i < THREADS
  # A fixed 22-character salt per thread: "$2a$04$" + one letter repeated.
  letter = ("A".ord + i).chr
  salt = "$2a$04$" + letter * 21 + "."
  secret = "secret-" + i.to_s
  salts << salt
  secrets << secret
  expected << BCrypt::Engine.hash_secret(secret, salt)
  i += 1
end

threads = []
t = 0
while t < THREADS
  threads << Thread.new(t) do |n|
    wrong = 0
    bad_salts = 0
    r = 0
    while r < ROUNDS
      got = BCrypt::Engine.hash_secret(secrets[n], salts[n])
      wrong += 1 if got != expected[n]
      s = BCrypt::Engine.generate_salt(4)
      bad_salts += 1 unless BCrypt::Engine.valid_salt?(s) && s.length == 29
      r += 1
    end
    [wrong, bad_salts]
  end
  t += 1
end

wrong = 0
bad_salts = 0
threads.each do |th|
  pair = th.value
  wrong += pair[0]
  bad_salts += pair[1]
end

puts "threads: #{THREADS} x #{ROUNDS}"
puts "digests not the thread's own: #{wrong}"
puts "malformed salts: #{bad_salts}"
