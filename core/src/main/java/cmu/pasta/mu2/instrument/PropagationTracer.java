package cmu.pasta.mu2.instrument;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Runtime tracer used by ASM-inserted hooks.
 *
 * Design goals:
 * - extremely low overhead when disabled (fast checks)
 * - no CFG build; only label hits are recorded
 * - trace window: after mutation point, within the current method only
 *
 * Notes:
 * - For original program (CCL) enable ONE mutant id per rerun (setEnabledSingle),
 *   and Cartographer-instrumented code calls maybeStartAfterInsn(id, methodId).
 * - For mutant program (MCL) we forceStart(id, methodId) right after replacement instruction.
 */
public final class PropagationTracer {

    private PropagationTracer() {}

    /** enabled mutant ids for the current test execution (thread-local). */
    private static final ThreadLocal<int[]> ENABLED_IDS =
            ThreadLocal.withInitial(() -> new int[0]);

    /** active tracing state (thread-local). */
    private static final ThreadLocal<State> STATE =
            ThreadLocal.withInitial(State::new);

    /** completed signatures (thread-local map keyed by mutant id). */
    private static final ThreadLocal<Map<Integer, PropagationTraceSig>> DONE =
            ThreadLocal.withInitial(HashMap::new);

    private static final class State {
        boolean active;
        int activeMutantId;
        int activeMethodId;
        long hash;
        int steps;

        // avoid starting same mutant multiple times in same run
        int startedMutantId = Integer.MIN_VALUE;

        void reset() {
            active = false;
            activeMutantId = 0;
            activeMethodId = 0;
            hash = 0L;
            steps = 0;
        }
    }

    // CCL 每个 seed 执行前设置
    /** Called by guidance before running the ORIGINAL program rerun for propagation signatures. */
    // 在“单次 CCL rerun 想同时收集多个 mutant 的 origSig”时才需要
    public static void setEnabledMutants(int[] mutantIds) {
        if (mutantIds == null || mutantIds.length == 0) {
            ENABLED_IDS.set(new int[0]);
            return;
        }
        int[] copy = Arrays.copyOf(mutantIds, mutantIds.length);
        Arrays.sort(copy);
        ENABLED_IDS.set(copy);
    }

    /** Convenience: enable only a single mutant id for a mutant run / a single CCL rerun. */
    // CCL 每次 rerun 只追 1 个 mutant
    public static void setEnabledSingle(int mutantId) {
        ENABLED_IDS.set(new int[]{mutantId});
    }

    /** Clear thread-local state and signatures (call at start of each trial). */
    public static void clearAll() {
        State s = STATE.get();
        s.reset();
        s.startedMutantId = Integer.MIN_VALUE;
        DONE.get().clear();
    }

    private static boolean isEnabled(int mutantId) {
        int[] ids = ENABLED_IDS.get();
        if (ids.length == 0) return false;
        return Arrays.binarySearch(ids, mutantId) >= 0;
    }

    // CCL 在机会点调用（只做 pending）
    // CCL在变异点之后开启跟踪 并初始化路径哈希
    /**
     * Start tracing after the mutation point for ORIGINAL program.
     * Inserted after the original instruction.
     *
     * IMPORTANT: This implementation does NOT support tracing multiple mutants in one CCL rerun.
     * Use setEnabledSingle(id) and rerun CCL per id.
     */
    public static void maybeStartAfterInsn(int mutantId, int methodId) {
        if (!isEnabled(mutantId)) return;

        State s = STATE.get();

        // If already tracing, do not override current trace (prevents losing sig)
        // 确保CCL一次只跟踪一个变异点的路径
        if (s.active) return;

        // Avoid repeated starts for same mutant (loops)
        if (s.startedMutantId == mutantId) return;
        s.startedMutantId = mutantId;

        s.active = true;
        s.activeMutantId = mutantId;
        s.activeMethodId = methodId;
        s.hash = mix64(0x9E3779B97F4A7C15L ^ mutantId ^ ((long) methodId << 32));
        s.steps = 0;
    }

    // MCL 在 mutation 替换后调用（立即启动） 并初始化路径哈希
    /** Start tracing after mutation point for MUTANT program (always). */
    public static void forceStart(int mutantId, int methodId) {
        State s = STATE.get();
        // 如果已经在跟踪，就不要覆盖（避免循环内多次重置）
        if (s.active) return;
        // 防止同一 mutant 在同一次运行里重复启动
        if (s.startedMutantId == mutantId) return;
        s.startedMutantId = mutantId;
        s.active = true;
        s.activeMutantId = mutantId;
        s.activeMethodId = methodId;
        s.hash = mix64(0xD6E8FEB86659FD93L ^ mutantId ^ ((long) methodId << 32));
        s.steps = 0;
    }

    /** Hit a label (instrumented at visitLabel). */
    public static void hitLabel(int methodId, int labelId) {
        State s = STATE.get();
        if (!s.active) return;
        if (s.activeMethodId != methodId) return;

        long x = ((long) labelId << 1) ^ (labelId * 0x9E3779B9L); // 把 labelId 做简单扩展，避免 labelId 的低位模式太强。
        s.hash = mix64(s.hash ^ x);
        s.steps++; // 路径长度 作为补充信息
    }

    /** End trace at method exit (RETURN/ATHROW). */
    // 在方法退出（RETURN/ATHROW）插桩调用。 把当前 trace 固化为 (hash, steps)，按 mutantId 存入 DONE。
    public static void endIfActive(int methodId) {
        State s = STATE.get();
        if (!s.active) return;
        if (s.activeMethodId != methodId) return;

        DONE.get().put(s.activeMutantId, new PropagationTraceSig(s.hash, s.steps));
        s.reset();
    }

    // 只读不删，适合在同一次run中多次读取
    public static PropagationTraceSig getSig(int mutantId) {
        return DONE.get().get(mutantId);
    }

    // 读取并删除，适合“消费一次就丢”，避免 map 变大。
    public static PropagationTraceSig popSig(int mutantId) {
        return DONE.get().remove(mutantId);
    }

    private static long mix64(long z) {
        z = (z ^ (z >>> 33)) * 0xff51afd7ed558ccdL;
        z = (z ^ (z >>> 33)) * 0xc4ceb9fe1a85ec53L;
        return z ^ (z >>> 33);
    }
}