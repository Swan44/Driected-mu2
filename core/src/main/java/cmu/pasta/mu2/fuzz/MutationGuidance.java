package cmu.pasta.mu2.fuzz;

import cmu.pasta.mu2.instrument.MutationTimeoutException;
import cmu.pasta.mu2.instrument.PropagationTraceSig;
import cmu.pasta.mu2.instrument.PropagationTracer;

import cmu.pasta.mu2.instrument.MutationInstance;
import cmu.pasta.mu2.instrument.MutationClassLoaders;
import cmu.pasta.mu2.instrument.OptLevel;
import cmu.pasta.mu2.util.ArraySet;
import edu.berkeley.cs.jqf.fuzz.difffuzz.DiffException;
import edu.berkeley.cs.jqf.fuzz.difffuzz.DiffFuzzGuidance;
import edu.berkeley.cs.jqf.fuzz.difffuzz.Outcome;
import edu.berkeley.cs.jqf.fuzz.difffuzz.Serializer;
import edu.berkeley.cs.jqf.fuzz.ei.ZestGuidance;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.guidance.Result;
import edu.berkeley.cs.jqf.fuzz.junit.TrialRunner;
import edu.berkeley.cs.jqf.fuzz.util.MovingAverage;
import edu.berkeley.cs.jqf.instrument.InstrumentationException;

import org.eclipse.collections.impl.set.mutable.primitive.IntHashSet;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.TestClass;

/**
 * Guidance that performs mutation-guided fuzzing
 *
 * @author Bella Laybourn
 * @author Rafaello Sanna
 * @author Rohan Padhye
 */
public class MutationGuidance extends ZestGuidance implements DiffFuzzGuidance {

  /**
   * The classloaders for cartography and individual mutation instances 单个变异实例的类加载器
   */
  protected MutationClassLoaders mutationClassLoaders;


  /**
   * Number of threads used to run mutants.
   */
  private static int BACKGROUND_THREADS = Integer.getInteger("mu2.BACKGROUND_THREADS", Runtime.getRuntime().availableProcessors());


  /**
   * Timeout for each mutant (DEFAULT: 10 seconds).
   */
  private static int TIMEOUT = Integer.getInteger("mu2.TIMEOUT", 10);

  public static boolean RUN_MUTANTS_IN_PARALLEL = Boolean.getBoolean("mu2.PARALLEL");

  private static final boolean PROP_FORCE_END = Boolean.getBoolean("mu2.prop.forceEnd");

  /**
   * The mutants killed so far
   */
  protected ArraySet deadMutants = new ArraySet();

  /**
   * The number of actual runs of the test 测试运行总次数
   */
  protected long numRuns = 0;

  /**
   * The number of runs done in the last interval 上个间隔内运行次数？
   */
  protected long lastNumRuns = 0;

  /**
   * The total time spent in the cartography class loader
   */
  protected long mappingTime = 0;

  /**
   * The total time spent running the tests
   */
  protected long testingTime = 0;

  /**
   * The size of the moving averages
   */
  protected static final int MOVING_AVERAGE_CAP = 10;

  /**
   * The number of mutants run in the most recent test runs
   */
  protected MovingAverage recentRun = new MovingAverage(MOVING_AVERAGE_CAP);

  /**
   * Current optimization level
   */
  protected final OptLevel optLevel;

  private final ExecutorService executor = Executors.newFixedThreadPool(BACKGROUND_THREADS);

  /**
   * The set of mutants to execute for a given trial.
   *
   * This is used when the optLevel is set to something higher than NONE,
   * in order to selectively choose which mutants are interesting for a given
   * input. This may include already killed mutants; those are skipped separately.
   *
   * This set must be reset/cleared before execution of every new input.
   */

  protected Method compare; // 用于比较结果的Method对象

  protected final List<String> mutantExceptionList = new ArrayList<>();

  protected final List<MutantFilter> filters = new ArrayList<>();

  protected ArraySet mutantsToRun = new ArraySet();

  // ---- NEW: per-trial original signatures & distances for selected mutants ----
  private final Map<Integer, PropagationTraceSig> origSigs = new HashMap<>();
  private final Map<Integer, Integer> propDistances = new HashMap<>();

  // seed score
  private static final class PropMeta {
    final double D;
    final double N;
    final double score;
    final long execMillis;
    final int size;
    final int numMutants;
    final boolean hasSignal;
    final Map<Integer, Double> hatDists;

    PropMeta(double D,
             double N,
             double score,
             long execMillis,
             int size,
             int numMutants,
             boolean hasSignal,
             Map<Integer, Double> hatDists) {
      this.D = D;
      this.N = N;
      this.score = score;
      this.execMillis = execMillis;
      this.size = size;
      this.numMutants = numMutants;
      this.hasSignal = hasSignal;
      this.hatDists = hatDists;
    }
  }

  private final Map<Input, PropMeta> propMeta =
          Collections.synchronizedMap(new WeakHashMap<>());



  // --- Propagation scoring parameters (tunable via system properties) ---
  // private static final int PROP_TOPK = Integer.getInteger("mu2.PROP_TOPK", 5);
  // private static final int PROP_MIN_MUTANTS = Integer.getInteger("mu2.PROP_MIN_MUTANTS", 5);
  private static final int PROP_TOPK_FLOOR =
          Integer.getInteger("mu2.PROP_TOPK_FLOOR", 2);

  private static final int PROP_TOPK_CAP =
          Integer.getInteger("mu2.PROP_TOPK_CAP", 5);

  private static final double PROP_TOPK_RATIO =
          Double.parseDouble(System.getProperty("mu2.PROP_TOPK_RATIO", "0.3"));

  private int currentPropTopK = PROP_TOPK_CAP;
  // 动态门槛：至少要求本轮参与传播计算 mutant 数的一定比例，同时设置一个绝对下限
  private static final int PROP_MIN_MUTANTS_FLOOR =
          Integer.getInteger("mu2.PROP_MIN_MUTANTS_FLOOR", 3);

  private static final double PROP_MIN_MUTANTS_RATIO =
          Double.parseDouble(System.getProperty("mu2.PROP_MIN_MUTANTS_RATIO", "0.5"));

  // 当前 trial 对应的动态门槛，在 run() 中按 selected.size() 更新
  private int currentPropMinMutants = PROP_MIN_MUTANTS_FLOOR;

  // rescue-save gate: only allow a small number of strong propagation-only seeds into corpus
  private static final double PROP_RESCUE_TH_D = Double.parseDouble(System.getProperty("mu2.PROP_RESCUE_TH_D", "0.80"));
  private static final double PROP_RESCUE_TH_N = Double.parseDouble(System.getProperty("mu2.PROP_RESCUE_TH_N", "0.08"));

  // propagation-based favored gate should be stricter than save gate
  private static final double PROP_FAV_STRONG_D = Double.parseDouble(System.getProperty("mu2.PROP_FAV_STRONG_D", "0.85"));
  private static final double PROP_FAV_STRONG_N = Double.parseDouble(System.getProperty("mu2.PROP_FAV_STRONG_N", "0.06"));
  private static final double PROP_FAV_N_ONLY   = Double.parseDouble(System.getProperty("mu2.PROP_FAV_N_ONLY",   "0.12"));

  // propagation measurements that are too slow should not gain bonus
  private static final long PROP_MAX_EXEC_MS = Long.getLong("mu2.PROP_MAX_EXEC_MS", 50L);

  // novelty gate: only gains above bestDist + eps count as real novelty
  private static final double NOVELTY_EPS = Double.parseDouble(System.getProperty("mu2.NOVELTY_EPS", "0.004"));

  // energy shaping (small bounded bonus instead of aggressive multiplicative explosion)
  private static final double ENERGY_GAMMA = Double.parseDouble(System.getProperty("mu2.ENERGY_GAMMA", "1.20"));
  private static final double ENERGY_MAX_MULT = Double.parseDouble(System.getProperty("mu2.ENERGY_MAX_MULT", "2.0"));
  private static final int ENERGY_CHILD_MAX = Integer.getInteger("mu2.ENERGY_CHILD_MAX", 3000);

  // score weights
  private static final double W_KILL = Double.parseDouble(System.getProperty("mu2.W_KILL", "2.0"));
  private static final double W_COV  = Double.parseDouble(System.getProperty("mu2.W_COV",  "1.0"));
  private static final double W_D    = Double.parseDouble(System.getProperty("mu2.W_D",    "1.0"));
  private static final double W_N    = Double.parseDouble(System.getProperty("mu2.W_N",    "2.2"));
  private static final double W_T    = Double.parseDouble(System.getProperty("mu2.W_T",    "0.4"));
  private static final double W_SZ   = Double.parseDouble(System.getProperty("mu2.W_SZ",   "0.2"));

  // TDGF-style local reranking on top of Zest queue semantics
  private static final int SELECT_WINDOW = Integer.getInteger("mu2.SELECT_WINDOW", 16);
  private static final double SELECT_COST_W = Double.parseDouble(System.getProperty("mu2.SELECT_COST_W", "0.10"));

  // annealing / exploitation strength
  private static final double SCHED_ANNEAL_K = Double.parseDouble(System.getProperty("mu2.SCHED_ANNEAL_K", "3.0"));

  // energy scaling based on utility relative to average utility
  private static final double ENERGY_COST_W = Double.parseDouble(System.getProperty("mu2.ENERGY_COST_W", "0.15"));

  // --- bestDist persistence ---
  private final File bestDistFile;
  private final Map<Integer, Double> bestDist = new HashMap<>(); // mutantId -> best hat_d in [0,1]
  private long bestDistDirtyWrites = 0;

  // --- tau estimator (robust scale for saturation) ---
  private final ArrayDeque<Integer> recentRawDists = new ArrayDeque<>();
  private static final int RECENT_DISTS_CAP = Integer.getInteger("mu2.PROP_RECENT_CAP", 200);

  // --- per-trial computed info ---
  private long lastTrialMillis = -1;
  private String lastPlotDataLine = null;

  // --- log variable ---

  // === path / distance ===
  protected File pathDiffFile;
  protected PrintWriter pathDiffLog;

  // === seed score ===
  protected File seedScoreFile;
  protected PrintWriter seedScoreLog;

  // === schedule / energy ===

  protected File scheduleDecisionFile;
  protected PrintWriter scheduleDecisionLog;

  protected File cycleSummaryFile;
  protected PrintWriter cycleSummaryLog;

  protected File propCountersFile;
  protected PrintWriter propCountersLog;

  // === counters / summaries ===
  protected long numPathSigCollected = 0;
  protected long numPathDiffComputed = 0;
  protected long numScheduleDecisions = 0;
  protected long numPathSigMiss = 0;
  protected long numDistNaN = 0;

  // 用于 summary
  protected long lastCycleKilled = 0;

  // 第一次杀死 mutant 时的 trial（或 run）编号
  protected long firstKillTrial = -1;

  private int computeDynamicPropMinMutants(int selectedCount) {
    if (selectedCount <= 0) {
      return PROP_MIN_MUTANTS_FLOOR;
    }
    int dynamic = (int) Math.ceil(selectedCount * PROP_MIN_MUTANTS_RATIO);
    return Math.max(PROP_MIN_MUTANTS_FLOOR, dynamic);
  }

  private int computeDynamicPropTopK(int selectedCount) {
    if (selectedCount <= 0) {
      return PROP_TOPK_FLOOR;
    }
    int dynamic = (int) Math.ceil(selectedCount * PROP_TOPK_RATIO);
    dynamic = Math.max(PROP_TOPK_FLOOR, dynamic);
    return Math.min(PROP_TOPK_CAP, dynamic);
  }

  // ======= bestDist IO =======
// “真正保存 seed 进 corpus”时触发更新
  private void loadBestDist() {
    if (!bestDistFile.exists()) return;
    try (DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(bestDistFile)))) {
      int n = in.readInt();
      for (int i = 0; i < n; i++) {
        int id = in.readInt();
        double v = in.readDouble();
        if (v < 0) v = 0;
        if (v > 1) v = 1;
        bestDist.put(id, v);
      }
      infoLog("Loaded bestDist entries: %d", bestDist.size());
    } catch (IOException e) {
      infoLog("Warning: failed to load bestDist: %s", e.toString());
    }
  }

  private void saveBestDist() {
    try (DataOutputStream out = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(bestDistFile)))) {
      out.writeInt(bestDist.size());
      for (Map.Entry<Integer, Double> e : bestDist.entrySet()) {
        out.writeInt(e.getKey());
        out.writeDouble(e.getValue());
      }
      out.flush();
    } catch (IOException e) {
      infoLog("Warning: failed to save bestDist: %s", e.toString());
    }
  }


  public MutationGuidance(String testName, MutationClassLoaders mutationClassLoaders,
                          Duration duration, Long trials, File outputDirectory, File seedInputDir, Random rand)
          throws IOException {
    super(testName, duration, trials, outputDirectory, seedInputDir, rand);
    this.mutationClassLoaders = mutationClassLoaders;
    this.totalCoverage = new MutationCoverage();
    this.runCoverage = new MutationCoverage();
    this.validCoverage = new MutationCoverage();
    this.optLevel = mutationClassLoaders.getCartographyClassLoader().getOptLevel();
// new
    this.bestDistFile = new File(outputDirectory, ".mu2_bestdist.bin");
    loadBestDist();
    this.pathDiffFile = new File(outputDirectory, "path-diff.csv");
    this.seedScoreFile = new File(outputDirectory, "seed-score.csv");
    this.scheduleDecisionFile = new File(outputDirectory, "schedule-decisions.csv");
    this.cycleSummaryFile = new File(outputDirectory, "cycle-summary.csv");
    this.propCountersFile = new File(outputDirectory, "prop-counters.csv");

    // 删除旧文件
    pathDiffFile.delete();
    seedScoreFile.delete();
    scheduleDecisionFile.delete();
    cycleSummaryFile.delete();
    propCountersFile.delete();

    // 写 header
    pathDiffLog = new PrintWriter(new FileWriter(pathDiffFile, true));
    pathDiffLog.println(
            "ts,trial,cycle,parentId,childId," +
                    "parentSigHash,childSigHash," +
                    "rawDist,normDist,distOrigMut,targetsSize"
    );
    pathDiffLog.flush();

    seedScoreLog = new PrintWriter(new FileWriter(seedScoreFile, true));
    seedScoreLog.println(
            "trial,currentParentInputId,D,N,score,numMutants,execMs,inputSize"
    );
    seedScoreLog.flush();

    cycleSummaryLog = new PrintWriter(new FileWriter(cycleSummaryFile, true));
    cycleSummaryLog.println(
            "ts,cycle,numSaved,numFavored," +
                    "parentIdx,reason,killedThisCycle"
    );
    cycleSummaryLog.flush();

    scheduleDecisionLog = new PrintWriter(new FileWriter(scheduleDecisionFile, true));
    scheduleDecisionLog.println(
            "ts,cycle,numSaved,numFavored," +
                    "parentIdx,reason,energy(score),pathDiffUsed"
    );
    scheduleDecisionLog.flush();

    propCountersLog = new PrintWriter(new FileWriter(propCountersFile, true));
    propCountersLog.println(
            "ts,cycle,trial,startCalled,hitLabelCalled,hitLabelEffective," +
                    "endCalled,forceEndCalled,sigFinalized,startSkippedDisabled," +
                    "startSkippedActive,startSkippedRepeated,endMethodMismatch"
    );
    propCountersLog.flush();

    filters.add(new DeadMutantsFilter(this));
    if(optLevel != OptLevel.NONE){
      filters.add(new PIEMutantFilter(this,optLevel));
    }
    try {
      compare = Objects.class.getMethod("equals", Object.class, Object.class);
    } catch (NoSuchMethodException e) {
      e.printStackTrace();
    }
  }

  /** Add filters to be used (in addition to PIE and DeadMutants) */
  public void addFilters (List<MutantFilter> additionalFilters){
    filters.addAll(additionalFilters);
  }

  /** Get number of mutants seen so far */
  public int getSeenMutants() {
    return ((MutationCoverage) totalCoverage).numSeenMutants();
  }

  /** Retreive the latest list of mutation instances */ // 检索最新的变异体列表
  protected List<MutationInstance> getMutationInstances() {
    // The latest list is available in the cartography class loader, which runs the initial test execution
    return mutationClassLoaders.getCartographyClassLoader().getMutationInstances();
  }

  public void setCompare(Method m) {
    compare = m;
  }

  /**
   * The names to be written to the top of the stats file
   */
  @Override
  protected String getStatNames() {
    return super.getStatNames()
            + ", found_muts, dead_muts, seen_muts, run_muts, total_time, map_time";
  }

  // 返回已满足非故障输入的保存条件的列表
  @Override
  protected List<String> checkSavingCriteriaSatisfied(Result result) {
    List<String> criteria = super.checkSavingCriteriaSatisfied(result);
    int newKilledMutants = ((MutationCoverage) totalCoverage).updateMutants(((MutationCoverage) runCoverage));
    if (newKilledMutants > 0) {
      criteria.add(String.format("+%d mutants %s", newKilledMutants, mutantExceptionList.toString()));
      currentInput.setFavored();
    }

    boolean hasNewCov = false;
    for (String s : criteria) {
      if (s.equals("+cov") || s.equals("+valid")) {
        hasNewCov = true;
        break;
      }
    }

    PropMeta meta = computePropMeta(newKilledMutants, hasNewCov);
    propMeta.put(currentInput, meta);

    boolean onlyCount = (criteria.size() == 1 && criteria.contains("+count"));
    boolean weakPropagation = !meta.hasSignal || (meta.D < 0.55 && meta.N < 0.03);
    if (onlyCount && weakPropagation) {
      criteria.clear();
    }

    boolean baseSaved = !criteria.isEmpty();
    boolean allowInvalid = (result == Result.SUCCESS) || (result == Result.INVALID && !SAVE_ONLY_VALID);

    // If the input is already worth saving for the base guidance, only annotate it with propagation info.
    if (baseSaved && allowInvalid && meta.hasSignal) {
      criteria.add(String.format("+prop(D=%.3f,N=%.3f,S=%.3f)", meta.D, meta.N, meta.score));
    }

    // Propagation-only rescue save: be very conservative.
    boolean allowPropRescue =
            !baseSaved &&
                    allowInvalid &&
                    meta.hasSignal &&
                    meta.numMutants >= currentPropMinMutants &&
                    meta.execMillis > 0 &&
                    meta.execMillis <= PROP_MAX_EXEC_MS &&
                    meta.D >= PROP_RESCUE_TH_D &&
                    meta.N >= PROP_RESCUE_TH_N;

    if (allowPropRescue) {
      criteria.add(String.format("+prop(D=%.3f,N=%.3f,S=%.3f)", meta.D, meta.N, meta.score));
    }

    // Propagation-based favored should remain high-precision / low-recall.
    boolean propFav =
            meta.hasSignal &&
                    meta.numMutants >= currentPropMinMutants &&
                    meta.execMillis > 0 &&
                    meta.execMillis <= PROP_MAX_EXEC_MS &&
                    ((meta.D >= PROP_FAV_STRONG_D && meta.N >= PROP_FAV_STRONG_N) ||
                            (meta.N >= PROP_FAV_N_ONLY));

    if (propFav) {
      currentInput.setFavored();
    }

    seedScoreLog.printf(
            "%d,%d,%.4f,%.4f,%.4f,%d,%d,%d\n",
            numTrials,
            currentParentInputIdx,
            meta.D,
            meta.N,
            meta.score,
            meta.numMutants,
            meta.execMillis,
            currentInput.size()
    );
    seedScoreLog.flush();
    return criteria;
  }

  private static final class MutantRunResult {
    final MutationInstance instance;
    final Outcome outcome;
    final PropagationTraceSig sig; // may be null

    MutantRunResult(MutationInstance instance, Outcome outcome, PropagationTraceSig sig) {
      this.instance = instance;
      this.outcome = outcome;
      this.sig = sig;
    }
  }

  private static int safeDistance(PropagationTraceSig orig, PropagationTraceSig mut) {
    if (orig == null || mut == null) return -1;
    try {
      return PropagationTraceSig.distance(orig, mut);
    } catch (Throwable t) {
      return -1;
    }
  }

  public MutantRunResult dispatchMutationInstanceWithSig(
          MutationInstance instance,
          TestClass testClass,
          byte[] argBytes,
          Object[] args,
          FrameworkMethod method)
          throws InvocationTargetException, IllegalAccessException,
          IOException, ClassNotFoundException, NoSuchMethodException {

    instance.resetTimer();
    MutationRunInfo mri = new MutationRunInfo(
            mutationClassLoaders, instance, testClass, argBytes, args, method);

    PropagationTracer.clearAll();
    PropagationTracer.setEnabledSingle(instance.id);

    Outcome out;
    PropagationTraceSig sig = null;

    try {
      TrialRunner dtr = new TrialRunner(mri.clazz, mri.method, mri.args);
      dtr.run();

      if (dtr.getOutput() == null) {
        out = new Outcome(null, null);
      } else {
        out = new Outcome(
                Serializer.translate(dtr.getOutput(),
                        mutationClassLoaders.getCartographyClassLoader()),
                null
        );
      }
    } catch (InstrumentationException e) {
      throw new GuidanceException(e);
    } catch (GuidanceException e) {
      throw e;
    } catch (Throwable e) {
      out = new Outcome(null, e);
    } finally {
      // sig 必须在执行线程里取
      try {
        if (PROP_FORCE_END) {
          PropagationTracer.forceEndIfActive();
        }
        sig = PropagationTracer.getSig(instance.id);
      } catch (Throwable ignore) {
        sig = null;
      } finally {
        // 防止该线程复用时残留
        PropagationTracer.clearAll();
      }
    }

    return new MutantRunResult(instance, out, sig);
  }

  private void enablePropagationForSelectedIds(int[] selectedIds) {
    try {
      Method m = PropagationTracer.class.getMethod("setEnabled", int[].class);
      m.invoke(null, (Object) selectedIds);
      return;
    } catch (Throwable ignore) {
      // fall through
    }

    try {
      Method m = PropagationTracer.class.getMethod("setEnabledIds", int[].class);
      m.invoke(null, (Object) selectedIds);
      return;
    } catch (Throwable ignore) {
      // fall through
    }

    throw new GuidanceException("PropagationTracer does not support batch enabling selected ids.");
  }

  private Map<Integer, PropagationTraceSig> snapshotOriginalPropagationSigs(int[] selectedIds) {
    Map<Integer, PropagationTraceSig> result = new HashMap<>(selectedIds.length);
    for (int id : selectedIds) {
      try {
        result.put(id, PropagationTracer.getSig(id));
      } catch (Throwable ignore) {
        result.put(id, null);
      }
    }
    return result;
  }

  private void collectOriginalPropagationSigs(TestClass testClass,
                                              FrameworkMethod method,
                                              Object[] args,
                                              int[] selectedIds) throws Throwable {
    PropagationTracer.clearAll();
    try {
      enablePropagationForSelectedIds(selectedIds);
      getOutcome(testClass.getJavaClass(), method, args);
      origSigs.putAll(snapshotOriginalPropagationSigs(selectedIds));
      numRuns += 1; // one extra original rerun collects signatures for all selected mutants together
    } catch (GuidanceException ge) {
      // Fallback for older tracer implementations: rerun once per mutant.
      for (int id : selectedIds) {
        PropagationTraceSig s = null;
        try {
          PropagationTracer.clearAll();
          PropagationTracer.setEnabledSingle(id);
          getOutcome(testClass.getJavaClass(), method, args);
          try {
            s = PropagationTracer.getSig(id);
          } catch (Throwable ignore) {
            s = null;
          }
          numRuns += 1;
        } finally {
          PropagationTracer.clearAll();
        }
        origSigs.put(id, s);
      }
    } finally {
      PropagationTracer.clearAll();
    }
  }

// 用于 propagation 选择：只负责选 10 个“最近最少执行”的 mutant 做路径度量
  // private final KLeastExecutedFilter propKLeastExecuted = new KLeastExecutedFilter(10);

  @Override
  public void run(TestClass testClass, FrameworkMethod method, Object[] args) throws Throwable {
    // 运行计数加1
    numRuns++;
    // 清空变异体异常列表
    mutantExceptionList.clear();
    // 重置要运行的变异体状态
    mutantsToRun.reset();
    // ---- NEW: reset propagation-trace state (per trial) ----
    origSigs.clear();
    propDistances.clear();
    PropagationTracer.clearAll();
    // 记录开始时间
    long startTime = System.currentTimeMillis();

    long mappingStart = System.currentTimeMillis();

    //run with CCL 运行原始测试
    Outcome cclOutcome = getOutcome(testClass.getJavaClass(), method, args);

    // set up info 原始测试运行时间 序列化参数 实际运行的变异体计数

    byte[] argBytes = Serializer.serialize(args);
    int run = 0;
    // 获取所有可用的变异体实例
    List<MutationInstance> mutationInstances = getMutationInstances();
    // 应用过滤器筛选变异体
    for(MutantFilter filter : filters){
      mutationInstances = filter.filterMutants(mutationInstances);
    }

    // ---- NEW: choose mutants for propagation distance ----
    List<MutationInstance> selected = mutationInstances;
    int[] selectedIds = selected.stream().mapToInt(mi -> mi.id).toArray();

    currentPropMinMutants = computeDynamicPropMinMutants(selected.size());
    currentPropTopK = computeDynamicPropTopK(selected.size());

    if (cclOutcome.thrown == null && selectedIds.length > 0) {
      collectOriginalPropagationSigs(testClass, method, args, selectedIds);
    }

    long mappingElapsed = System.currentTimeMillis() - mappingStart;
    mappingTime += mappingElapsed;

    // 存储所有变异体运行结果的列表
    List<MutantRunResult> results = new ArrayList<>();
    if (RUN_MUTANTS_IN_PARALLEL) {
      List<Future<MutantRunResult>> futures = selected
              .stream()
              .map(instance ->
                      executor.submit(() ->
                              // keep enabled single to reduce stray starts
                              dispatchMutationInstanceWithSig(instance, testClass, argBytes, args, method)))
              .collect(Collectors.toList());
      // Use for loop to capture exceptions.
      for (int i = 0; i < futures.size(); i++) {
        Future<MutantRunResult> future = futures.get(i);
        MutationInstance inst = selected.get(i);
        try {
          results.add(future.get(TIMEOUT, TimeUnit.SECONDS));
        } catch (TimeoutException te) {
          future.cancel(true);
          results.add(new MutantRunResult(
                  inst,
                  new Outcome(null, new MutationTimeoutException(TIMEOUT)),
                  null
          ));
        }
      }
    } else {
      for (MutationInstance instance: selected) {
        results.add(dispatchMutationInstanceWithSig(instance, testClass, argBytes, args, method));
      }
    }
// 分析变异体执行结果，判断哪些变异体被杀死了（被检测出来）
    for (MutantRunResult r : results) {
      Outcome mclOutcome = r.outcome;
      if (mclOutcome == null) continue;
      run +=1; // 计数实际运行的变异体
      MutationInstance instance = r.instance;

      // ---- NEW: compute distance only if this mutant is in selected set ----
      PropagationTraceSig mutSig = r.sig;
      PropagationTraceSig origSig = origSigs.get(instance.id);
      int dist = safeDistance(origSig, mutSig);
      if (dist >= 0) {
        propDistances.put(instance.id, dist);
        pushRecentDist(dist);
      }

      numPathDiffComputed++;
      if (origSig == null || mutSig == null) {
        numPathSigMiss++;
      } else if (dist < 0) {
        numDistNaN++;
      } else {
        numPathSigCollected++;
        long ts = System.currentTimeMillis() / 1000;
        int cycle = cyclesCompleted;
        int parentId = currentParentInputIdx;

        pathDiffLog.printf(
                "%d,%d,%d,%d,%d,%d,%d,%d,%.4f,%d,%d\n",
                ts,
                numTrials,
                cycle,
                parentId,
                -1, // childId (预留)
                origSig.hashCode(),
                mutSig.hashCode(),
                dist,
                robustNorm(dist),
                dist,            // distOrigMut
                origSigs.size()  // targetsSize
        );
        pathDiffLog.flush();
      }

      // MCL outcome and CCL outcome should be the same (either returned same value or threw same exception)
      // If this isn't the case, the mutant is killed.
      // This catches validity differences because an invalid input throws an AssumptionViolatedException,
      // which will be compared as the thrown value.
      if(!Outcome.same(cclOutcome, mclOutcome, compare)) {
        deadMutants.add(instance.id);
        if (firstKillTrial < 0) {
          firstKillTrial = numTrials;
        }
        Throwable t;
        if(cclOutcome.thrown == null && mclOutcome.thrown != null) {
          // CCL succeeded, MCL threw an exception 原始代码成功，变异体抛出异常
          t = mclOutcome.thrown;
        } else {
          // 其他不一致情况（如返回值不同）
          t = new DiffException(cclOutcome, mclOutcome);
        }
        // 记录变异体异常信息
        mutantExceptionList.add("(" + instance.toString() + ", " +  t.getClass().getName()+")");
        // 在覆盖率中标记该变异体被杀死
        ((MutationCoverage) runCoverage).kill(instance);
      }

      // run // 记录该变异体被执行过（无论是否被杀死）
      ((MutationCoverage) runCoverage).see(instance);

    }

    //throw exception if an exception was found by the CCL 如果原始测试本身抛出了异常，重新抛出
    if(cclOutcome.thrown != null) throw cclOutcome.thrown;
    // 计算总的运行时间
    long completeTime = System.currentTimeMillis() - startTime;
    lastTrialMillis = completeTime;

    recentRun.add(run); // 记录本次运行的变异体数量
    //mappingTime += trialTime;
    testingTime += completeTime;
    numRuns += run; // 累加变异体运行次数
  }

  // ======= propagation scoring core =======
  private void pushRecentDist(int d) {
    if (d < 0) return;
    recentRawDists.addLast(d);
    while (recentRawDists.size() > RECENT_DISTS_CAP) {
      recentRawDists.removeFirst();
    }
  }

  private double estimateTau() {
    if (recentRawDists.isEmpty()) return 32.0; // stable fallback for typical rawDist range
    int[] arr = new int[recentRawDists.size()];
    int i = 0;
    for (int v : recentRawDists) arr[i++] = v;
    Arrays.sort(arr);
    int idx = (int) Math.floor(0.75 * (arr.length - 1));
    return Math.max(8.0, arr[idx]);
  }

  private double normTime(long ms) {
    if (ms <= 0) return 0.0;
    double ref = 20.0;
    return ms / (ms + ref);
  }

  private double normSize(int sz) {
    if (sz <= 0) return 0.0;
    double ref = 64.0;
    return sz / (sz + ref);
  }

  private double estimateQuantile(double q) {
    if (recentRawDists.isEmpty()) return 0.0;
    int[] arr = new int[recentRawDists.size()];
    int i = 0;
    for (int v : recentRawDists) arr[i++] = v;
    Arrays.sort(arr);
    int idx = (int) Math.floor(q * (arr.length - 1));
    idx = Math.max(0, Math.min(arr.length - 1, idx));
    return arr[idx];
  }

  private double robustNorm(int d) {
    if (d <= 0) return 0.0;
    if (recentRawDists.size() < 8) {
      return saturateNorm(d, estimateTau());
    }
    double q10 = estimateQuantile(0.10);
    double q90 = estimateQuantile(0.90);
    if (q90 <= q10 + 1.0) {
      return saturateNorm(d, estimateTau());
    }
    double x = (d - q10) / (q90 - q10);
    if (x < 0.0) return 0.0;
    if (x > 1.0) return 1.0;
    return x;
  }

  private static double saturateNorm(int d, double tau) {
    if (d <= 0) return 0.0;
    return d / (d + tau);
  }

  private static double topKAverage(List<Double> vals, int k) {
    if (vals.isEmpty()) return 0.0;
    vals.sort(Collections.reverseOrder());
    int kk = Math.min(k, vals.size());
    double s = 0.0;
    for (int i = 0; i < kk; i++) s += vals.get(i);
    return s / kk;
  }

  /**
   * Compute D(s), N(s), Score(s) based on propDistances for currentInput.
   * Side-channel version (Scheme A): does NOT write into Input.
   *
   * @param deltaKill number of new killed mutants in this trial
   * @param hasNewCov whether this trial increases coverage (e.g., +cov/+valid/+count)
   * @return PropMeta containing D, N, score and hat distances
   */
  private PropMeta computePropMeta(int deltaKill, boolean hasNewCov) {

    if (propDistances == null || propDistances.isEmpty()) {
      double score =
              (deltaKill > 0 ? W_KILL : 0.0) +
                      (hasNewCov ? W_COV : 0.0);

      return new PropMeta(
              0.0,
              0.0,
              score,
              lastTrialMillis,
              currentInput.size(),
              0,
              false,
              Collections.emptyMap()
      );
    }

    Map<Integer, Double> hatDists = new HashMap<>(propDistances.size());
    List<Double> hatList = new ArrayList<>(propDistances.size());

    for (Map.Entry<Integer, Integer> e : propDistances.entrySet()) {
      int mid = e.getKey();
      int d = (e.getValue() == null ? 0 : e.getValue());
      if (d <= 0) {
        continue;
      }
      double hat = robustNorm(d);
      hatDists.put(mid, hat);
      hatList.add(hat);
    }

    int numMutants = hatDists.size();
    if (numMutants == 0) {
      double score =
              (deltaKill > 0 ? W_KILL : 0.0) +
                      (hasNewCov ? W_COV : 0.0);
      return new PropMeta(
              0.0,
              0.0,
              score,
              lastTrialMillis,
              currentInput.size(),
              0,
              false,
              Collections.emptyMap()
      );
    }

    double D = topKAverage(hatList, currentPropTopK);

    List<Double> gains = new ArrayList<>(numMutants);
    for (Map.Entry<Integer, Double> e : hatDists.entrySet()) {
      int mid = e.getKey();
      double hat = e.getValue();
      double best = bestDist.getOrDefault(mid, 0.0);
      double gain = hat - best;
      if (gain > NOVELTY_EPS) {
        gains.add(gain);
      }
    }
    double N = gains.isEmpty() ? 0.0 : topKAverage(gains, Math.min(currentPropTopK, 3));

    double tNorm = normTime(lastTrialMillis);
    double sNorm = normSize(currentInput.size());

    double score =
            (deltaKill > 0 ? W_KILL : 0.0) +
                    (hasNewCov ? W_COV : 0.0) +
                    W_D * D +
                    W_N * N -
                    W_T * tNorm -
                    W_SZ * sNorm;

    boolean hasSignal =
            numMutants >= currentPropMinMutants &&
                    lastTrialMillis > 0;

    return new PropMeta(
            D,
            N,
            score,
            lastTrialMillis,
            currentInput.size(),
            numMutants,
            hasSignal,
            hatDists
    );
  }

  /*
  并建议在 fuzz 结束（或 EXIT_ON_CRASH）前保存一次；一个简单办法是：在 hasInput() 里即将返回 false 时做 save（但你目前 hasInput 在父类）。最小改法：在 displayStats(force=true) 或者 completeCycle() 偶尔保存一次。下面我放在 completeCycle() 里做一次：
   */
  @Override
  protected void saveCurrentInput(IntHashSet responsibilities, String why) throws IOException {
    super.saveCurrentInput(responsibilities, why);

    PropMeta meta = propMeta.get(currentInput);
    if (meta == null || meta.hatDists == null || meta.hatDists.isEmpty()) {
      return;
    }

    boolean shouldUpdateBest =
            meta.hasSignal &&
                    why != null &&
                    (why.contains("+prop") || why.contains("mutants"));

    if (!shouldUpdateBest) {
      return;
    }

    boolean updated = false;
    for (Map.Entry<Integer, Double> e : meta.hatDists.entrySet()) {
      int mid = e.getKey();
      double hat = e.getValue();
      double old = bestDist.getOrDefault(mid, 0.0);
      if (hat > old) {
        bestDist.put(mid, hat);
        updated = true;
      }
    }

    if (updated) {
      bestDistDirtyWrites++;
      if (bestDistDirtyWrites % 25 == 0) {
        saveBestDist();
      }
    }
  }

  // 种子选择：cycle 结束后按 propScore 排序 savedInputs（优先轮询高分种子）
  private double currentAnnealFactor() {
    if (maxDurationMillis == Long.MAX_VALUE) {
      double pseudo = Math.min(1.0, numTrials / 100000.0);
      return 1.0 - Math.exp(-SCHED_ANNEAL_K * pseudo);
    }
    long elapsed = Math.max(0L, new Date().getTime() - startTime.getTime());
    double progress = Math.min(1.0, elapsed / (double) Math.max(1L, maxDurationMillis));
    return 1.0 - Math.exp(-SCHED_ANNEAL_K * progress);
  }

  private double propagationUtility(PropMeta meta) {
    if (meta == null || !meta.hasSignal) {
      return 0.0;
    }
    double noveltyBoost = Math.min(1.0, meta.N * 4.0);
    double u = 0.70 * meta.D + 0.30 * noveltyBoost;
    if (u < 0.0) return 0.0;
    if (u > 1.0) return 1.0;
    return u;
  }

  private double propagationCost(PropMeta meta) {
    if (meta == null) return 0.0;
    double t = normTime(meta.execMillis);
    double s = normSize(meta.size);
    return 0.5 * t + 0.5 * s;
  }

  private double averageUtility() {
    if (savedInputs.isEmpty()) return 0.0;
    double sum = 0.0;
    int cnt = 0;
    for (Input in : savedInputs) {
      PropMeta meta = propMeta.get(in);
      if (meta != null && meta.hasSignal) {
        sum += propagationUtility(meta);
        cnt++;
      }
    }
    return cnt == 0 ? 0.0 : (sum / cnt);
  }

  private EnergyDecision computeEnergyDecision(Input parentInput) {
    int base = super.getTargetChildrenForParent(parentInput);
    PropMeta meta = propMeta.get(parentInput);
    double util = propagationUtility(meta);
    double avgUtil = averageUtility();
    double rho = currentAnnealFactor();
    double cost = propagationCost(meta);

    if (meta == null || !meta.hasSignal || avgUtil <= 0.0) {
      return new EnergyDecision(base, util, 1.0);
    }

    double relative = util / Math.max(1e-9, avgUtil);
    double mult = (1.0 + ENERGY_GAMMA * rho * (relative - 1.0)) / (1.0 + ENERGY_COST_W * cost);
    if (mult > ENERGY_MAX_MULT) mult = ENERGY_MAX_MULT;
    if (mult < 0.65) mult = 0.65;

    long scaled = (long) Math.ceil(base * mult);
    if (scaled > ENERGY_CHILD_MAX) scaled = ENERGY_CHILD_MAX;
    if (scaled < 1) scaled = 1;

    return new EnergyDecision((int) scaled, util, mult);
  }

  private void logEnergyDecisionForCurrentParent() {
    if (savedInputs.isEmpty()) return;
    Input parent = savedInputs.get(currentParentInputIdx);
    EnergyDecision d = computeEnergyDecision(parent);
    scheduleDecisionLog.printf(
            "%d,%d,%d,%d,%d,%s,%.4f,%.4f\n",
            System.currentTimeMillis() / 1000,
            cyclesCompleted,
            numSavedInputs,
            numFavoredLastCycle,
            currentParentInputIdx,
            "energy",
            d.util,
            d.mult
    );
    scheduleDecisionLog.flush();
  }

  private static final class EnergyDecision {
    final int children;
    final double util;
    final double mult;

    EnergyDecision(int children, double util, double mult) {
      this.children = children;
      this.util = util;
      this.mult = mult;
    }
  }

  private int selectParentIndexFromWindow(int startIdx) {
    if (savedInputs.isEmpty()) return 0;
    final int n = savedInputs.size();
    final int window = Math.min(SELECT_WINDOW, n);
    final double rho = currentAnnealFactor();

    int[] idxs = new int[window];
    double maxBase = 1.0;
    for (int i = 0; i < window; i++) {
      int idx = (startIdx + i) % n;
      idxs[i] = idx;
      int base = super.getTargetChildrenForParent(savedInputs.get(idx));
      if (base > maxBase) {
        maxBase = base;
      }
    }

    int bestIdx = idxs[0];
    double bestScore = Double.NEGATIVE_INFINITY;
    for (int idx : idxs) {
      Input in = savedInputs.get(idx);
      PropMeta meta = propMeta.get(in);
      double baseNorm = super.getTargetChildrenForParent(in) / maxBase;
      double util = propagationUtility(meta);
      double cost = propagationCost(meta);
      double score = (1.0 - rho) * baseNorm + rho * util - SELECT_COST_W * cost;
      if (score > bestScore) {
        bestScore = score;
        bestIdx = idx;
      }
    }

    scheduleDecisionLog.printf(
            "%d,%d,%d,%d,%d,%s,%.4f,%.4f\n",
            System.currentTimeMillis() / 1000,
            cyclesCompleted,
            numSavedInputs,
            numFavoredLastCycle,
            bestIdx,
            "window_select",
            bestScore,
            rho
    );
    scheduleDecisionLog.flush();

    return bestIdx;
  }

  @Override
  public InputStream getInput() throws GuidanceException {
    conditionallySynchronize(multiThreaded, () -> {
      runCoverage.clear();

      if (!seedInputs.isEmpty()) {
        currentInput = seedInputs.removeFirst();
      } else if (savedInputs.isEmpty()) {
        if (!blind && numTrials > 100_000) {
          throw new GuidanceException("Too many trials without coverage; likely all assumption violations");
        }
        currentInput = createFreshInput();
      } else {
        Input currentParentInput = savedInputs.get(currentParentInputIdx);
        int targetNumChildren = computeEnergyDecision(currentParentInput).children;
        if (numChildrenGeneratedForCurrentParentInput >= targetNumChildren) {
          int startIdx = (currentParentInputIdx + 1) % savedInputs.size();
          if (startIdx == 0) {
            completeCycle();
          }
          currentParentInputIdx = selectParentIndexFromWindow(startIdx);
          numChildrenGeneratedForCurrentParentInput = 0;
        }

        if (numChildrenGeneratedForCurrentParentInput == 0) {
          logEnergyDecisionForCurrentParent();
        }

        Input parent = savedInputs.get(currentParentInputIdx);
        currentInput = parent.fuzz(random);
        numChildrenGeneratedForCurrentParentInput++;

        try {
          writeCurrentInputToFile(currentInputFile);
        } catch (IOException ignore) {
        }

        this.runStart = new Date();
        this.branchCount = 0;
      }
    });

    return createParameterStream();
  }

  @Override
  protected void completeCycle() {
    super.completeCycle();

    // Do not reorder savedInputs globally; preserve original Zest queue semantics.
    saveBestDist();

    long killedNow = deadMutants.size();
    long killedThisCycle = killedNow - lastCycleKilled;
    lastCycleKilled = killedNow;

    cycleSummaryLog.printf(
            "%d,%d,%d,%d,%d,%s,%d\n",
            System.currentTimeMillis() / 1000,
            cyclesCompleted,
            numSavedInputs,
            numFavoredLastCycle,
            -1,
            "cycle_summary",
            killedThisCycle
    );
    cycleSummaryLog.flush();
  }

  // 能量调度：在原 coverage 能量基础上乘距离因子
  // baseline -> coverage fraction -> favored *20。
  @Override
  protected int getTargetChildrenForParent(Input parentInput) {
    return computeEnergyDecision(parentInput).children;
  }


  @Override
  protected void displayStats(boolean force) {
    Date now = new Date();
    long intervalTime = Math.max(1L, now.getTime() - lastRefreshTime.getTime());
    long totalTime = Math.max(1L, now.getTime() - startTime.getTime());

    if (intervalTime < STATS_REFRESH_TIME_PERIOD && !force) {
      return;
    }

    double trialsPerSec = numTrials * 1000.0 / totalTime;
    long intervalTrials = numTrials - lastNumTrials;
    double intervalTrialsPerSec = intervalTrials * 1000.0 / intervalTime;

    double runsPerSec = numRuns * 1000.0 / totalTime;
    long intervalRuns = numRuns - lastNumRuns;
    double intervalRunsPerSec = intervalRuns * 1000.0 / intervalTime;

    lastRefreshTime = now;
    lastNumTrials = numTrials;
    lastNumRuns = numRuns;

    String currentParentInputDesc;
    if (seedInputs.size() > 0 || savedInputs.isEmpty()) {
      currentParentInputDesc = "<seed>";
    } else {
      Input currentParentInput = savedInputs.get(currentParentInputIdx);
      currentParentInputDesc = currentParentInputIdx + " ";
      currentParentInputDesc += currentParentInput.isFavored() ? "(favored)" : "(not favored)";
      currentParentInputDesc += " {" + numChildrenGeneratedForCurrentParentInput +
              "/" + getTargetChildrenForParent(currentParentInput) + " mutations}";
    }

    int nonZeroCount = totalCoverage.getNonZeroCount();
    double nonZeroFraction = nonZeroCount * 100.0 / totalCoverage.size();
    int nonZeroValidCount = validCoverage.getNonZeroCount();
    double nonZeroValidFraction = nonZeroValidCount * 100.0 / validCoverage.size();
    int totalFound = getMutationInstances().size();

    if (console != null) {
      if (LIBFUZZER_COMPAT_OUTPUT) {
        console.printf("#%,d\tNEW\tcov: %,d exec/s: %,d L: %,d\n", numTrials, nonZeroValidCount,
                (long) intervalTrialsPerSec, currentInput.size());
      } else if (!QUIET_MODE) {
        console.printf("\033[2J");
        console.printf("\033[H");
        console.printf(this.getTitle() + "\n");
        if (this.testName != null) {
          console.printf("Test name:            %s\n", this.testName);
        }
        console.printf("Results directory:    %s\n", this.outputDirectory.getAbsolutePath());
        console.printf("Elapsed time:         %s (%s)\n", millisToDuration(totalTime),
                maxDurationMillis == Long.MAX_VALUE ? "no time limit"
                        : ("max " + millisToDuration(maxDurationMillis)));
        console.printf("Number of trials:     %,d\n", numTrials);
        console.printf("Number of executions: %,d\n", numRuns);
        console.printf("Valid inputs:         %,d (%.2f%%)\n", numValid, numTrials == 0 ? 0.0 : numValid * 100.0 / numTrials);
        console.printf("Cycles completed:     %d\n", cyclesCompleted);
        console.printf("Unique failures:      %,d\n", uniqueFailures.size());
        console.printf("Queue size:           %,d (%,d favored last cycle)\n", savedInputs.size(), numFavoredLastCycle);
        console.printf("Current parent input: %s\n", currentParentInputDesc);
        console.printf("Fuzzing Throughput:   %,d/sec now | %,d/sec overall\n", (long) intervalTrialsPerSec, (long) trialsPerSec);
        console.printf("Execution Speed:      %,d/sec now | %,d/sec overall\n", (long) intervalRunsPerSec, (long) runsPerSec);
        console.printf("Testing Time:         %s\n", millisToDuration(testingTime));
        console.printf("Mapping Time:         %s (%.2f%% of testing)\n", millisToDuration(mappingTime), testingTime == 0 ? 0.0 : (double) mappingTime * 100.0 / (double) testingTime);
        console.printf("Found Mutants:        %d\n", totalFound);
        console.printf("Recent Run Mutants:   %.2f (%.2f%% of total)\n", recentRun.get(), totalFound == 0 ? 0.0 : recentRun.get() * 100.0 / totalFound);
        console.printf("Total coverage:       %,d branches (%.2f%% of map)\n", nonZeroCount, nonZeroFraction);
        console.printf("Valid coverage:       %,d branches (%.2f%% of map)\n", nonZeroValidCount, nonZeroValidFraction);
        console.printf("Killed mutants:       %,d\n", ((MutationCoverage) totalCoverage).numCaughtMutants());
        console.printf("Seen mutants:         %,d\n", ((MutationCoverage) totalCoverage).numSeenMutants());
      }
    }

    String plotData = String.format(
            "%d, %d, %d, %d, %d, %d, %.2f%%, %d, %d, %d, %.2f, %d, %d, %.2f%%, %d, %d, %d, %d, %d, %.2f, %d, %d",
            TimeUnit.MILLISECONDS.toSeconds(now.getTime()), cyclesCompleted, currentParentInputIdx,
            numSavedInputs, 0, 0, nonZeroFraction, uniqueFailures.size(), 0, 0, intervalTrialsPerSec,
            numValid, numTrials - numValid, nonZeroValidFraction, nonZeroCount, nonZeroValidCount,
            totalFound, deadMutants.size(), ((MutationCoverage) totalCoverage).numSeenMutants(),
            recentRun.get(), testingTime, mappingTime);
    if (!plotData.equals(lastPlotDataLine)) {
      appendLineToFile(statsFile, plotData);
      lastPlotDataLine = plotData;
    }

    try {
      if (propCountersLog != null) {
        cmu.pasta.mu2.instrument.PropagationTracer.Counters c =
                cmu.pasta.mu2.instrument.PropagationTracer.snapshotCounters();
        propCountersLog.printf(
                "%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
                TimeUnit.MILLISECONDS.toSeconds(now.getTime()),
                cyclesCompleted,
                numTrials,
                c.startCalled,
                c.hitLabelCalled,
                c.hitLabelEffective,
                c.endCalled,
                c.forceEndCalled,
                c.sigFinalized,
                c.startSkippedDisabled,
                c.startSkippedActive,
                c.startSkippedRepeated,
                c.endMethodMismatch
        );
        propCountersLog.flush();
      }
    } catch (Throwable ignore) {
    }

    if (force) {
      File summary = new File(outputDirectory, "summary.csv");
      try (PrintWriter pw = new PrintWriter(summary)) {
        pw.println("metric,value");
        pw.printf("firstKillTrial,%d\n", firstKillTrial);
        pw.printf("mutantsKilledTotal,%d\n", deadMutants.size());
        pw.printf("numRuns,%d\n", numRuns);
        pw.printf("cyclesCompleted,%d\n", cyclesCompleted);
        pw.printf("elapsedTimeSec,%d\n",
                TimeUnit.MILLISECONDS.toSeconds(
                        System.currentTimeMillis() - startTime.getTime()
                )
        );
      } catch (IOException e) {
        e.printStackTrace();
      } finally {
        try { saveBestDist(); } catch (Throwable ignore) {}
        try { if (pathDiffLog != null) pathDiffLog.close(); } catch (Throwable ignore) {}
        try { if (seedScoreLog != null) seedScoreLog.close(); } catch (Throwable ignore) {}
        try { if (cycleSummaryLog != null) cycleSummaryLog.close(); } catch (Throwable ignore) {}
        try { if (scheduleDecisionLog != null) scheduleDecisionLog.close(); } catch (Throwable ignore) {}
        try { if (propCountersLog != null) propCountersLog.close(); } catch (Throwable ignore) {}
      }
    }
  }
  @Override
  protected String getTitle() {
    if (blind) {
      return "Generator-based random fuzzing (no guidance)\n" +
              "--------------------------------------------\n";
    } else {
      return "Mutation-Guided & Driected Fuzzing\n" +
              "--------------------------\n";
    }
  }
}
