package cmu.pasta.mu2.instrument;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Runtime tracer used by ASM-inserted hooks.
 *
 * Design goals:
 * - extremely low overhead when disabled (fast checks)
 * - no CFG build; only lightweight event/transition sketches are recorded
 * - trace window: after mutation point, within the current method only
 *
 * Notes:
 * - For original program (CCL) enable ONE mutant id per rerun (setEnabledSingle),
 *   and Cartographer-instrumented code calls startAtMutationPoint(id, methodId).
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

        long nodeBitsLo;
        long nodeBitsHi;
        long edgeBitsLo;
        long edgeBitsHi;
        int steps;

        int lastLabelId;
        boolean hasLastLabel;

        int startedMutantId = Integer.MIN_VALUE;

        void resetActiveOnly() {
            active = false;
            activeMutantId = 0;
            activeMethodId = 0;

            nodeBitsLo = 0L;
            nodeBitsHi = 0L;
            edgeBitsLo = 0L;
            edgeBitsHi = 0L;
            steps = 0;

            lastLabelId = 0;
            hasLastLabel = false;
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

    private static void setBit128Node(State s, int labelId) {
        long h1 = mix64(0x9E3779B97F4A7C15L ^ (long) labelId);
        int idx1 = (int) (h1 & 127L);
        if (idx1 < 64) {
            s.nodeBitsLo |= (1L << idx1);
        } else {
            s.nodeBitsHi |= (1L << (idx1 - 64));
        }

        long h2 = mix64(0xC2B2AE3D27D4EB4FL ^ (long) labelId);
        int idx2 = (int) (h2 & 127L);
        if (idx2 < 64) {
            s.nodeBitsLo |= (1L << idx2);
        } else {
            s.nodeBitsHi |= (1L << (idx2 - 64));
        }
    }

    private static void setBit128Edge(State s, int prevLabelId, int curLabelId) {
        long edgeKey = (((long) prevLabelId) << 32) ^ (curLabelId & 0xffffffffL);

        long h1 = mix64(0x165667B19E3779F9L ^ edgeKey);
        int idx1 = (int) (h1 & 127L);
        if (idx1 < 64) {
            s.edgeBitsLo |= (1L << idx1);
        } else {
            s.edgeBitsHi |= (1L << (idx1 - 64));
        }

        long h2 = mix64(0x85EBCA77C2B2AE63L ^ edgeKey);
        int idx2 = (int) (h2 & 127L);
        if (idx2 < 64) {
            s.edgeBitsLo |= (1L << idx2);
        } else {
            s.edgeBitsHi |= (1L << (idx2 - 64));
        }
    }

    /** Called right before the mutation opportunity bytecode executes. */
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

        s.nodeBitsLo = 0L;
        s.nodeBitsHi = 0L;
        s.edgeBitsLo = 0L;
        s.edgeBitsHi = 0L;
        s.steps = 0;
        s.lastLabelId = 0;
        s.hasLastLabel = false;
    }

    public static void hitLabel(int methodId, int labelId) {
        Counters c = CNT.get();
        c.hitLabelCalled++;

        State s = STATE.get();
        if (!s.active) return;
        if (s.activeMethodId != methodId) return;

        c.hitLabelEffective++;

        setBit128Node(s, labelId);
        if (s.hasLastLabel) {
            setBit128Edge(s, s.lastLabelId, labelId);
        }

        s.lastLabelId = labelId;
        s.hasLastLabel = true;
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

        DONE.get().put(
                s.activeMutantId,
                new PropagationTraceSig(
                        s.nodeBitsLo,
                        s.nodeBitsHi,
                        s.edgeBitsLo,
                        s.edgeBitsHi,
                        s.steps
                )
        );
        c.sigFinalized++;
        s.resetActiveOnly();
    }

    public static void forceEndIfActive() {
        Counters c = CNT.get();
        c.forceEndCalled++;

        State s = STATE.get();
        if (!s.active) return;

        DONE.get().put(
                s.activeMutantId,
                new PropagationTraceSig(
                        s.nodeBitsLo,
                        s.nodeBitsHi,
                        s.edgeBitsLo,
                        s.edgeBitsHi,
                        s.steps
                )
        );
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