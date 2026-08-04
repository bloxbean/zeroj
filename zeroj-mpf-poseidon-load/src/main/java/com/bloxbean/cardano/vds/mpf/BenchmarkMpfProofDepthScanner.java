package com.bloxbean.cardano.vds.mpf;

import com.bloxbean.cardano.vds.core.NodeHash;
import com.bloxbean.cardano.vds.core.api.HashFunction;
import com.bloxbean.cardano.vds.core.api.NodeStore;
import com.bloxbean.cardano.vds.mpf.commitment.CommitmentScheme;

import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.LongConsumer;

/**
 * Benchmark-only current-root traversal that measures inclusion-proof branch depth.
 *
 * <p>This class deliberately lives in CCL's MPF package because the concrete node
 * types are package-private in CCL 0.8.0-pre5. It is part of the non-published load
 * module, not the public Poseidon MPF adapter. CCL folds an extension prefix into
 * the following branch proof record, so only branch nodes increase the inclusion
 * proof-step count. A root that is itself a leaf therefore has zero proof steps.</p>
 */
public final class BenchmarkMpfProofDepthScanner {
    private BenchmarkMpfProofDepthScanner() {}

    public static Result scan(
            NodeStore store,
            HashFunction hashFunction,
            CommitmentScheme commitmentScheme,
            byte[] root,
            long progressEvery,
            LongConsumer progress) {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(hashFunction, "hashFunction");
        Objects.requireNonNull(commitmentScheme, "commitmentScheme");
        Objects.requireNonNull(root, "root");
        if (progressEvery < 0) throw new IllegalArgumentException("progressEvery must be >= 0");

        NodePersistence persistence = new NodePersistence(store, commitmentScheme, hashFunction);
        Node rootNode = requireNode(persistence, root);
        Scanner scanner = new Scanner(persistence, progressEvery, progress == null ? ignored -> {} : progress);
        scanner.visit(rootNode, 0);
        return scanner.result();
    }

    private static Node requireNode(NodePersistence persistence, byte[] hash) {
        Node node = persistence.load(NodeHash.of(hash));
        if (node == null) {
            throw new IllegalStateException("MPF node referenced by the current root is missing");
        }
        return node;
    }

    private static final class Scanner {
        private final NodePersistence persistence;
        private final long progressEvery;
        private final LongConsumer progress;
        private final TreeMap<Integer, Long> histogram = new TreeMap<>();
        private long entries;
        private long branchValues;
        private long branches;
        private long extensions;
        private long visitedNodes;
        private int maxProofSteps;

        private Scanner(NodePersistence persistence, long progressEvery, LongConsumer progress) {
            this.persistence = persistence;
            this.progressEvery = progressEvery;
            this.progress = progress;
        }

        private void visit(Node node, int branchSteps) {
            visitedNodes++;
            if (node instanceof LeafNode) {
                recordEntry(branchSteps);
                return;
            }
            if (node instanceof BranchNode branch) {
                branches++;
                int childSteps = Math.addExact(branchSteps, 1);
                if (branch.getValue() != null) {
                    branchValues++;
                    recordEntry(childSteps);
                }
                for (byte[] child : branch.getChildren()) {
                    if (child != null && child.length > 0) {
                        visit(requireNode(persistence, child), childSteps);
                    }
                }
                return;
            }
            if (node instanceof ExtensionNode extension) {
                extensions++;
                byte[] child = extension.getChild();
                if (child == null || child.length == 0) {
                    throw new IllegalStateException("MPF extension has no child");
                }
                visit(requireNode(persistence, child), branchSteps);
                return;
            }
            throw new IllegalStateException("Unsupported MPF node type: " + node.getClass().getName());
        }

        private void recordEntry(int proofSteps) {
            entries++;
            maxProofSteps = Math.max(maxProofSteps, proofSteps);
            histogram.merge(proofSteps, 1L, Long::sum);
            if (progressEvery > 0 && entries % progressEvery == 0) progress.accept(entries);
        }

        private Result result() {
            return new Result(
                    entries,
                    branchValues,
                    branches,
                    extensions,
                    visitedNodes,
                    maxProofSteps,
                    Map.copyOf(histogram));
        }
    }

    public record Result(
            long entries,
            long branchValueEntries,
            long branchNodes,
            long extensionNodes,
            long visitedNodes,
            int maxProofSteps,
            Map<Integer, Long> stepHistogram) {}
}
