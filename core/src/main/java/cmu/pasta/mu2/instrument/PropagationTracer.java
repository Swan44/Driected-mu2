package cmu.pasta.mu2.instrument;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Runtime tracer used by ASM-inserted hooks.
 * Design goals:
 * - extremely low overhead when disabled (fast checks)
 * - no CFG build; only label hits are recorded
 * - trace window: after mutation point, within the current method only
 * Notes:
 * - For original program (CCL) enable ONE mutant id per rerun (setEnabledSingle),
 *   and Cartographer-instrumented code calls maybeStartAfterInsn(id, methodId).
 * - For mutant program (MCL) we forceStart(id, methodId) right after replacement instruction.
 */
public final class PropagationTracer {

    private PropagationTracer() {}

    private static final ThreadLocal<int[]> ENABLED_IDS =
            ThreadLocal.withInitial(() -> new int[0]);

    private static final ThreadLocal<State> STATE =
            ThreadLocal.withInitial(State::new);

    private static final ThreadLocal<Map<Integer, PropagationTraceSig>> DONE =
            ThreadLocal.withInitial(HashMap::new);

    public static final class Counters {
        public long startCalled;
        public long startSkippedDisabled;
        public long startSkippedActive;
        public long startSkippedRepeated;
        public long hitLabelCalled;
        public long hitLabelEffective;
        public long endCalled;
        public long endMethodMismatch;
        public long forceEndCalled;
        public long sigFinalized;
    }

    private static final ThreadLocal<Counters> CNT =
            ThreadLocal.withInitial(Counters::new);

    private static final class State {
        boolean active;
        int activeMutantId;
        int activeMethodId;
        long hash;
        int steps;
        int startedMutantId = Integer.MIN_VALUE;

        void resetActiveOnly() {
            active = false;
            activeMutantId = 0;
            activeMethodId = 0;
            hash = 0L;
            steps = 0;
        }

        void resetAll() {
            resetActiveOnly();
            startedMutantId = Integer.MIN_VALUE;
        }
    }

    public static void setEnabledSingle(int mutantId) {
        ENABLED_IDS.set(new int[]{mutantId});
    }

    public static void clearAll() {
        STATE.get().resetAll();
        DONE.get().clear();
    }

    private static boolean isEnabled(int mutantId) {
        int[] ids = ENABLED_IDS.get();
        if (ids.length == 0) return false;
        return Arrays.binarySearch(ids, mutantId) >= 0;
    }

    /** 统一：在 mutation opportunity 对应字节码执行前调用 */
    public static void startAtMutationPoint(int mutantId, int methodId) {
        Counters c = CNT.get();
        c.startCalled++;

        if (!isEnabled(mutantId)) {
            c.startSkippedDisabled++;
            return;
        }

        State s = STATE.get();
        if (s.active) {
            c.startSkippedActive++;
            return;
        }

        if (s.startedMutantId == mutantId) {
            c.startSkippedRepeated++;
            return;
        }

        s.startedMutantId = mutantId;
        s.active = true;
        s.activeMutantId = mutantId;
        s.activeMethodId = methodId;

        // 原程序和变异体必须一致
        s.hash = mix64(0x9E3779B97F4A7C15L ^ mutantId ^ (((long) methodId) << 32));
        s.steps = 0;
    }

    public static void hitLabel(int methodId, int labelId) {
        Counters c = CNT.get();
        c.hitLabelCalled++;

        State s = STATE.get();
        if (!s.active) return;
        if (s.activeMethodId != methodId) return;

        c.hitLabelEffective++;
        long x = ((long) labelId << 1) ^ (labelId * 0x9E3779B9L);
        s.hash = mix64(s.hash ^ x);
        s.steps++;
    }

    public static void endIfActive(int methodId) {
        Counters c = CNT.get();
        c.endCalled++;

        State s = STATE.get();
        if (!s.active) return;
        if (s.activeMethodId != methodId) {
            c.endMethodMismatch++;
            return;
        }

        DONE.get().put(s.activeMutantId, new PropagationTraceSig(s.hash, s.steps));
        c.sigFinalized++;
        s.resetActiveOnly();
    }

    public static void forceEndIfActive() {
        Counters c = CNT.get();
        c.forceEndCalled++;

        State s = STATE.get();
        if (!s.active) return;

        DONE.get().put(s.activeMutantId, new PropagationTraceSig(s.hash, s.steps));
        c.sigFinalized++;
        s.resetActiveOnly();
    }

    public static PropagationTraceSig getSig(int mutantId) {
        return DONE.get().get(mutantId);
    }

    public static Counters snapshotCounters() {
        Counters src = CNT.get();
        Counters dst = new Counters();
        dst.startCalled = src.startCalled;
        dst.startSkippedDisabled = src.startSkippedDisabled;
        dst.startSkippedActive = src.startSkippedActive;
        dst.startSkippedRepeated = src.startSkippedRepeated;
        dst.hitLabelCalled = src.hitLabelCalled;
        dst.hitLabelEffective = src.hitLabelEffective;
        dst.endCalled = src.endCalled;
        dst.endMethodMismatch = src.endMethodMismatch;
        dst.forceEndCalled = src.forceEndCalled;
        dst.sigFinalized = src.sigFinalized;
        return dst;
    }

    private static long mix64(long z) {
        z = (z ^ (z >>> 33)) * 0xff51afd7ed558ccdL;
        z = (z ^ (z >>> 33)) * 0xc4ceb9fe1a85ec53L;
        return z ^ (z >>> 33);
    }
}