class Crashwrangler < Formula
  desc "Capture, classify, analyze, and deduplicate macOS crashes"
  homepage "https://github.com/ant4g0nist/crashwrangler"
  url "https://github.com/ant4g0nist/crashwrangler.git",
      revision: "0686e7c0bf72c2329e4eca4244b564113a82563d"
  version "3.0.0"
  license all_of: ["Apache-2.0", :cannot_represent]
  head "https://github.com/ant4g0nist/crashwrangler.git", branch: "main"

  depends_on "rust" => :build
  depends_on arch: :arm64
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args
    bin.install_symlink "crashwrangler" => "exc_handler"
  end

  test do
    report = testpath/"write_bad_access.ips"
    report.write <<~EOS
      {"app_name":"fixture","build_version":"23Z1"}
      {"procName":"fixture","procPath":"/tmp/fixture","cpuType":"ARM-64","osVersion":{"build":"23Z1"},"exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV","subtype":"KERN_PROTECTION_FAILURE at 0x0000000041414141","rawCodes":[2,1094795585]},"faultingThread":0,"threads":[{"triggered":true,"threadState":{"pc":{"value":4294971392},"esr":{"value":2449473607}},"frames":[{"imageIndex":0,"imageOffset":4096,"symbol":"write_fixture","symbolLocation":16}]}],"usedImages":[{"name":"fixture","base":4294967296}]}
    EOS

    output = shell_output("#{bin}/crashwrangler analyze --json #{report}")
    assert_match '"access_type":"write"', output
    assert_match '"is_exploitable":"yes"', output
    assert_equal (bin/"crashwrangler").realpath, (bin/"exc_handler").realpath
  end
end
