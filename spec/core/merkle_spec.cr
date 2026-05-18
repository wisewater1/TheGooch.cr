require "../spec_helper"

describe TheGooch::Merkle do
  it "computes a stable root" do
    leaves = ["a", "b", "c", "d"]
    TheGooch::Merkle.root(leaves).should eq(TheGooch::Merkle.root(leaves))
  end

  it "handles odd leaves via duplication" do
    leaves = ["a", "b", "c"]
    root = TheGooch::Merkle.root(leaves)
    root.size.should eq(64)
  end

  it "proofs verify and tampering fails" do
    leaves = ["a", "b", "c", "d"]
    root = TheGooch::Merkle.root(leaves)
    proof = TheGooch::Merkle.proof_for(leaves, 2)
    TheGooch::Merkle.verify("c", proof, root).should be_true
    TheGooch::Merkle.verify("x", proof, root).should be_false
  end
end
