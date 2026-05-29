# typed: false
# frozen_string_literal: true

class Chainsaw < Formula
  desc "Supply chain security scanner for CRA compliance"
  homepage "https://github.com/jessequinn/chainsaw-cli"
  url "https://github.com/jessequinn/chainsaw-cli/archive/refs/tags/v0.4.0.tar.gz"
  sha256 "PLACEHOLDER"
  license "Apache-2.0"

  head "https://github.com/jessequinn/chainsaw-cli.git", branch: "main"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X main.version=#{version}
    ]
    system "go", "build", *std_go_args(ldflags:), "./cmd/chainsaw"

    generate_completions_from_executable(bin/"chainsaw", "completion")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/chainsaw version")

    assert_match "scan", shell_output("#{bin}/chainsaw --help")

    (testpath/"go.mod").write <<~EOS
      module example.com/test

      go 1.21
    EOS
    system bin/"chainsaw", "scan", testpath.to_s
  end

  livecheck do
    url :stable
    regex(/^v?(\d+(?:\.\d+)+)$/i)
    strategy :github_latest
  end
end
