package cmu.pasta.mu2.instrument;

/*
    轻量的路径签名结构
    “变异点之后、变异函数内的控制流/执行轨迹”

 */

/** Lightweight path signature for propagation tracing (within a method after mutation point). */
public final class PropagationTraceSig {
    public final long hash; // 轨迹哈希：每遇到一个“路径事件”（label / jump / switch / line）就做一次混合（mix）
    // 每记录一次事件+1
    public final int steps;   // number of labels hit while tracing 步数（大致的执行长度/复杂度 proxy）

    public PropagationTraceSig(long hash, int steps) {
        this.hash = hash;
        this.steps = steps;
    }

    public static PropagationTraceSig empty() {
        return new PropagationTraceSig(0L, 0);
    }

    /** Very cheap distance: hamming(hash) + small weight * abs(steps diff). */
    public static int distance(PropagationTraceSig a, PropagationTraceSig b) {
        if (a == null) a = empty();
        if (b == null) b = empty();
        int ham = Long.bitCount(a.hash ^ b.hash);
        int len = Math.abs(a.steps - b.steps);// steps 差异作为弱权重项补充（避免 hash 偶然碰撞或路径长度变化不被体现）
        // length diff is weaker than control-flow signature diff
        return ham + (len >>> 2);
    }

    @Override
    public String toString() {
        return "PropagationTraceSig{hash=" + Long.toUnsignedString(hash) + ", steps=" + steps + "}";
    }
}

