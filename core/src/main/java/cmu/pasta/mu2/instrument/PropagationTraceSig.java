package cmu.pasta.mu2.instrument;

/*
    轻量的传播路径签名结构
    表示“变异点之后、变异函数内”的局部执行行为：
    1) 访问到哪些路径事件（node/event set）
    2) 观察到哪些相邻转移（edge/transition set）
    3) 总步数 steps（执行长度 proxy）
 */

/** Lightweight path signature for propagation tracing (within a method after mutation point). */
public final class PropagationTraceSig {

    /** bitset of visited labels/events (128 bits). */
    public final long nodeBitsLo;
    public final long nodeBitsHi;

    /** bitset of observed local transitions prevLabel -> curLabel (128 bits). */
    public final long edgeBitsLo;
    public final long edgeBitsHi;

    /** number of labels hit while tracing; used as a weak path-length feature. */
    public final int steps;

    /** weights for the structured propagation distance. */
    private static final double NODE_W =
            Double.parseDouble(System.getProperty("mu2.PROP_NODE_W", "0.40"));
    private static final double EDGE_W =
            Double.parseDouble(System.getProperty("mu2.PROP_EDGE_W", "0.40"));
    private static final double STEP_W =
            Double.parseDouble(System.getProperty("mu2.PROP_STEP_W", "0.20"));

    /** scale double distance to int so existing guidance code can still consume int rawDist. */
    private static final int DIST_SCALE =
            Integer.getInteger("mu2.PROP_DIST_SCALE", 1000);

    public PropagationTraceSig(long nodeBitsLo,
                               long nodeBitsHi,
                               long edgeBitsLo,
                               long edgeBitsHi,
                               int steps) {
        this.nodeBitsLo = nodeBitsLo;
        this.nodeBitsHi = nodeBitsHi;
        this.edgeBitsLo = edgeBitsLo;
        this.edgeBitsHi = edgeBitsHi;
        this.steps = steps;
    }

    public static PropagationTraceSig empty() {
        return new PropagationTraceSig(0L, 0L, 0L, 0L, 0);
    }

    private static double jaccard128(long alo, long ahi, long blo, long bhi) {
        long interLo = alo & blo;
        long interHi = ahi & bhi;
        long unionLo = alo | blo;
        long unionHi = ahi | bhi;

        int inter = Long.bitCount(interLo) + Long.bitCount(interHi);
        int union = Long.bitCount(unionLo) + Long.bitCount(unionHi);

        if (union == 0) {
            return 1.0; // both empty => identical
        }
        return ((double) inter) / union;
    }

    /**
     * Structured propagation distance:
     *   D = α * (1 - J_nodes) + β * (1 - J_edges) + γ * normalizedStepDiff
     *
     * Returns an int scaled by DIST_SCALE so existing code paths that expect an int rawDist
     * can continue to work with minimal changes.
     */
    public static int distance(PropagationTraceSig a, PropagationTraceSig b) {
        if (a == null) a = empty();
        if (b == null) b = empty();

        double nodeDist = 1.0 - jaccard128(a.nodeBitsLo, a.nodeBitsHi, b.nodeBitsLo, b.nodeBitsHi);
        double edgeDist = 1.0 - jaccard128(a.edgeBitsLo, a.edgeBitsHi, b.edgeBitsLo, b.edgeBitsHi);

        int maxSteps = Math.max(Math.max(a.steps, b.steps), 1);
        double stepDist = ((double) Math.abs(a.steps - b.steps)) / maxSteps;

        double d = NODE_W * nodeDist + EDGE_W * edgeDist + STEP_W * stepDist;
        if (d < 0.0) d = 0.0;
        if (d > 1.0) d = 1.0;

        return (int) Math.round(d * DIST_SCALE);
    }

    @Override
    public String toString() {
        return "PropagationTraceSig{" +
                "nodeBitsLo=" + Long.toUnsignedString(nodeBitsLo) +
                ", nodeBitsHi=" + Long.toUnsignedString(nodeBitsHi) +
                ", edgeBitsLo=" + Long.toUnsignedString(edgeBitsLo) +
                ", edgeBitsHi=" + Long.toUnsignedString(edgeBitsHi) +
                ", steps=" + steps +
                "}";
    }
}
