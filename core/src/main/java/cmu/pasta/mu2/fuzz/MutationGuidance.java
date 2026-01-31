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
    final Map<Integer, Double> hatDists;

    PropMeta(double D,
             double N,
             double score,
             long execMillis,
             int size,
             Map<Integer, Double> hatDists) {
      this.D = D;
      this.N = N;
      this.score = score;
      this.execMillis = execMillis;
      this.size = size;
      this.hatDists = hatDists;
    }
  }

  private final Map<Input, PropMeta> propMeta =
          Collections.synchronizedMap(new WeakHashMap<>());



  // --- Propagation scoring parameters (tunable via system properties) ---
  private static final int PROP_TOPK = Integer.getInteger("mu2.PROP_TOPK", 5);
  // private static final int PROP_SAVE_K = Integer.getInteger("mu2.PROP_SAVE_K", 10);
  private static final double PROP_SAVE_TH_D = Double.parseDouble(System.getProperty("mu2.PROP_SAVE_TH_D", "0.60"));
  private static final double PROP_SAVE_TH_N = Double.parseDouble(System.getProperty("mu2.PROP_SAVE_TH_N", "0.05"));
  private static final double PROP_FAV_TH_D = Double.parseDouble(System.getProperty("mu2.PROP_FAV_TH_D", "0.75"));
  private static final double PROP_FAV_TH_N = Double.parseDouble(System.getProperty("mu2.PROP_FAV_TH_N", "0.08"));

  // energy shaping
  private static final double ENERGY_ALPHA = Double.parseDouble(System.getProperty("mu2.ENERGY_ALPHA", "1.0"));
  private static final double ENERGY_BETA  = Double.parseDouble(System.getProperty("mu2.ENERGY_BETA",  "2.0"));
  private static final int ENERGY_CHILD_MAX = Integer.getInteger("mu2.ENERGY_CHILD_MAX", 5000);

  // score weights
  private static final double W_KILL = Double.parseDouble(System.getProperty("mu2.W_KILL", "2.0"));
  private static final double W_COV  = Double.parseDouble(System.getProperty("mu2.W_COV",  "1.0"));
  private static final double W_D    = Double.parseDouble(System.getProperty("mu2.W_D",    "1.0"));
  private static final double W_N    = Double.parseDouble(System.getProperty("mu2.W_N",    "1.5"));

  // --- bestDist persistence ---
  private final File bestDistFile;
  private final Map<Integer, Double> bestDist = new HashMap<>(); // mutantId -> best hat_d in [0,1]
  private long bestDistDirtyWrites = 0;

  // --- tau estimator (robust scale for saturation) ---
  private final ArrayDeque<Integer> recentRawDists = new ArrayDeque<>();
  private static final int RECENT_DISTS_CAP = Integer.getInteger("mu2.PROP_RECENT_CAP", 200);

  // --- per-trial computed info ---
  private long lastTrialMillis = -1;

  // --- log variable ---

  // === path / distance ===
  protected File pathDiffFile;
  protected PrintWriter pathDiffLog;

  // === seed score ===
  protected File seedScoreFile;
  protected PrintWriter seedScoreLog;

  // === schedule / energy ===
  protected File scheduleFile;
  protected PrintWriter scheduleLog;

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
    this.scheduleFile = new File(outputDirectory, "schedule.csv");

    // 删除旧文件
    pathDiffFile.delete();
    seedScoreFile.delete();
    scheduleFile.delete();

    // 写 header
    pathDiffLog = new PrintWriter(new FileWriter(pathDiffFile, true));
    pathDiffLog.println(
            "ts,trial,cycle,parentId,childId," +
                    "parentSigHash,childSigHash," +
                    "rawDist,normDist,distToTarget,targetsSize"
    );
    pathDiffLog.flush();

    seedScoreLog = new PrintWriter(new FileWriter(seedScoreFile, true));
    seedScoreLog.println(
            "trial,inputId,D,N,score,numMutants,execMs,inputSize"
    );
    seedScoreLog.flush();

    scheduleLog = new PrintWriter(new FileWriter(scheduleFile, true));
    scheduleLog.println(
            "ts,cycle,numSaved,numFavored," +
                    "parentIdx,reason,energy,scoreParent,pathDiffUsed"
    );
    scheduleLog.flush();

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

    // TODO: Add responsibilities for mutants killed

    // 判断是否有新的 coverage（近似：criteria 中是否包含）
    boolean hasNewCov = false;
    for (String s : criteria) {
      if (s.equals("+cov") || s.equals("+valid") || s.equals("+count")) {
        hasNewCov = true;
        break;
      }
    }

    // 计算 propagation side-channel metadata
    PropMeta meta = computePropMeta(newKilledMutants, hasNewCov);
    propMeta.put(currentInput, meta);

    // 5. distance-guided saving: +prop
    if (result == Result.SUCCESS ||
            (result == Result.INVALID && !SAVE_ONLY_VALID)) {

      if (meta.D >= PROP_SAVE_TH_D && meta.N >= PROP_SAVE_TH_N) {
        criteria.add(String.format(
                "+prop(D=%.3f,N=%.3f,S=%.3f)",
                meta.D, meta.N, meta.score
        ));
      }
    }

    // 6. distance-guided favored（复用 Zest *20 机制）
    if (meta.D >= PROP_FAV_TH_D || meta.N >= PROP_FAV_TH_N) {
      currentInput.setFavored();
    }

    seedScoreLog.printf(
            "%d,%d,%.4f,%.4f,%.4f,%d,%d,%d\n",
            numRuns,
            currentParentInputIdx,
            meta.D,
            meta.N,
            meta.score,
            propDistances.size(),
            meta.execMillis,
            currentInput.size()
    );
    seedScoreLog.flush();
    return criteria;
  }

  // 分发和执行变异体
  /**
   * @param instance 变异体示例
   * @param testClass 测试类
   * @param argBytes 参数的字节表示（用于序列化）？
   * @param args 参数数组
   * @param method 要执行的方法
   * @return 执行结果 Outcome对象
   */
  public Outcome dispatchMutationInstance(MutationInstance instance, TestClass testClass, byte[] argBytes,
                                          Object[] args, FrameworkMethod method)
          throws ExecutionException, InterruptedException, InvocationTargetException, IllegalAccessException,
          IOException, ClassNotFoundException, NoSuchMethodException {

    // update info 重置变异体执行时间计时器
    instance.resetTimer();
    // 创建变异体运行信息对象 封装执行所需的所所有信息 使用变异类加载器、变异体示实例、测试类、参数等信息
    MutationRunInfo mri = new MutationRunInfo(mutationClassLoaders, instance, testClass, argBytes, args, method);

    // run with MCL 异步执行变异体测试
    FutureTask<Outcome> task = new FutureTask<>(() -> {
      try {
        // 创建测试运行器 准备执行测试
        TrialRunner dtr = new TrialRunner(mri.clazz, mri.method, mri.args);
        dtr.run();
        if (dtr.getOutput() == null) return new Outcome(null, null);
        else {
          // 序列化输出并返回
          return new Outcome(Serializer.translate(dtr.getOutput(),
                  mutationClassLoaders.getCartographyClassLoader()), null);
        }
      } catch (InstrumentationException e) {
        throw new GuidanceException(e);
      } catch (GuidanceException e) {
        throw e;
      } catch (Throwable e) {
        return new Outcome(null, e);
      }
    });
    Outcome mclOutcome = null;

    if (RUN_MUTANTS_IN_PARALLEL) {

      Thread thread = new Thread(task);
      thread.start();

      ExecutorService service = Executors.newSingleThreadExecutor();
      Future<Outcome> outcome = service.submit(() -> task.get());

      try {
        // 设置超时等待，TIMEOUT秒内获取结果
        mclOutcome = outcome.get(TIMEOUT, TimeUnit.SECONDS);
      } catch (TimeoutException e) {
        thread.stop();
        mclOutcome = new Outcome(null, new MutationTimeoutException(TIMEOUT));
      }

      service.shutdownNow();
    } else { // 串行 直接在当前线程执行
      task.run();
      mclOutcome = task.get();
    }

    return mclOutcome;
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

  // 用于 propagation 选择：只负责选 10 个“最近最少执行”的 mutant 做路径度量
  private final KLeastExecutedFilter propKLeastExecuted = new KLeastExecutedFilter(10);


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

    //run with CCL 运行原始测试
    Outcome cclOutcome = getOutcome(testClass.getJavaClass(), method, args);

    // set up info 原始测试运行时间 序列化参数 实际运行的变异体计数
    long trialTime = System.currentTimeMillis() - startTime;
    byte[] argBytes = Serializer.serialize(args);
    int run = 0;
    // 获取所有可用的变异体实例
    List<MutationInstance> mutationInstances = getMutationInstances();
    // 应用过滤器筛选变异体
    for(MutantFilter filter : filters){
      mutationInstances = filter.filterMutants(mutationInstances);
    }

    // ---- NEW: choose top-K mutants for propagation distance (default 10) ----
    final int K = 10;
    List<MutationInstance> selected = propKLeastExecuted.filterMutants(mutationInstances);
    if (mutationInstances.size() > K) {
      selected = mutationInstances.subList(0, K);
    }
    int[] selectedIds = selected.stream().mapToInt(mi -> mi.id).toArray();

    // ---- NEW: rerun ORIGINAL program once, only enabling selected ids ----
    for (int id : selectedIds) {
      PropagationTracer.clearAll();
      PropagationTracer.setEnabledSingle(id);
      // This run is only for collecting orig propagation sig for this id
      getOutcome(testClass.getJavaClass(), method, args);
      PropagationTraceSig s = PropagationTracer.getSig(id);
      if (s != null) {
        origSigs.put(id, s);
      } else {
        // optional: record missing sig as empty to keep distance stable
        origSigs.put(id, PropagationTraceSig.empty());
      }
    }

    // 存储所有变异体运行结果的列表
    List<MutantRunResult> results = new ArrayList<>();
    if (RUN_MUTANTS_IN_PARALLEL) {
      List<Future<MutantRunResult>> futures = selected
              .stream()
              .map(instance ->
                      executor.submit(() ->
                      {
                        // keep enabled single to reduce stray starts
                        PropagationTracer.clearAll();
                        PropagationTracer.setEnabledSingle(instance.id);
                        Outcome out = dispatchMutationInstance(instance, testClass, argBytes, args, method);
                        PropagationTraceSig sig = PropagationTracer.getSig(instance.id);
                        return new MutantRunResult(instance, out, sig);
                      }))
              .collect(Collectors.toList());
      // Use for loop to capture exceptions.
      for (Future<MutantRunResult> future : futures) {
        results.add(future.get());
      }
    } else {
      for (MutationInstance instance: selected) {
        PropagationTracer.clearAll();
        PropagationTracer.setEnabledSingle(instance.id);
        Outcome out = dispatchMutationInstance(instance, testClass, argBytes, args, method);
        PropagationTraceSig sig = PropagationTracer.getSig(instance.id);
        results.add(new MutantRunResult(instance, out, sig));
      }
    }
// 分析变异体执行结果，判断哪些变异体被杀死了（被检测出来）
    for (MutantRunResult r : results) {
      Outcome mclOutcome = r.outcome;
      if (mclOutcome == null) continue;
      run +=1; // 计数实际运行的变异体
      MutationInstance instance = r.instance;

      // ---- NEW: compute distance only if this mutant is in selected set ----
      if (origSigs.containsKey(instance.id)) {
        PropagationTraceSig mutSig = r.sig;
        PropagationTraceSig origSig = origSigs.get(instance.id);
        int dist = PropagationTraceSig.distance(origSig, mutSig);
        propDistances.put(instance.id, dist);
      }

      numPathDiffComputed++;
      PropagationTraceSig mutSig = r.sig;
      PropagationTraceSig origSig = origSigs.get(instance.id);
      if (origSig == null || mutSig == null) {
        numPathSigMiss++;
      } else {
        int dist = PropagationTraceSig.distance(origSig, mutSig);
        if (dist < 0) {
          numDistNaN++;
        } else {
          numPathSigCollected++;
          long ts = System.currentTimeMillis() / 1000;
          int cycle = cyclesCompleted;
          int parentId = currentParentInputIdx;
          pathDiffLog.printf(
                  "%d,%d,%d,%d,%d,%d,%d,%d,%.4f,%d,%d\n",
                  ts,
                  numRuns,
                  cycle,
                  parentId,
                  -1, // childId (预留)
                  origSig.hashCode(),
                  mutSig.hashCode(),
                  dist,
                  saturateNorm(dist, estimateTau()),
                  dist,                 // distToTarget
                  origSigs.size()       // targetsSize
          );
        }
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
    mappingTime += trialTime;
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
    if (recentRawDists.isEmpty()) return 10.0; // fallback
    int[] arr = new int[recentRawDists.size()];
    int i = 0;
    for (int v : recentRawDists) arr[i++] = v;
    Arrays.sort(arr);
    int mid = arr.length / 2;
    double med = (arr.length % 2 == 1) ? arr[mid] : (arr[mid - 1] + arr[mid]) / 2.0;
    // avoid degenerate tau
    return Math.max(1.0, med);
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

    // ---------- Case 0: no propagation distances ----------
    if (propDistances == null || propDistances.isEmpty()) {
      double score =
              (deltaKill > 0 ? W_KILL : 0.0) +
                      (hasNewCov  ? W_COV  : 0.0);

      return new PropMeta(
              0.0,                    // D
              0.0,                    // N
              score,                  // score
              lastTrialMillis,        // exec time
              currentInput.size(),    // input size
              Collections.emptyMap()  // no hat distances
      );
    }

    // ---------- Step 1: update tau estimator ----------
    for (int d : propDistances.values()) {
      if (d >= 0) {
        pushRecentDist(d);
      }
    }
    double tau = estimateTau();

    // ---------- Step 2: build normalized (hat) distances ----------
    Map<Integer, Double> hatDists = new HashMap<>(propDistances.size());
    List<Double> hatList = new ArrayList<>(propDistances.size());

    for (Map.Entry<Integer, Integer> e : propDistances.entrySet()) {
      int mid = e.getKey();
      int d   = (e.getValue() == null ? 0 : e.getValue());
      double hat = saturateNorm(d, tau);
      hatDists.put(mid, hat);
      hatList.add(hat);
    }

    // ---------- Step 3: D(s) = top-k average ----------
    double D = topKAverage(hatList, PROP_TOPK);

    // ---------- Step 4: N(s) = novelty over bestDist ----------
    double gainSum = 0.0;
    int cnt = 0;
    for (Map.Entry<Integer, Double> e : hatDists.entrySet()) {
      int mid = e.getKey();
      double hat = e.getValue();
      double best = bestDist.getOrDefault(mid, 0.0);
      if (hat > best) {
        gainSum += (hat - best);
      }
      cnt++;
    }
    double N = (cnt == 0) ? 0.0 : (gainSum / cnt);

    // ---------- Step 5: unified score ----------
    double score =
            (deltaKill > 0 ? W_KILL : 0.0) +
                    (hasNewCov  ? W_COV  : 0.0) +
                    W_D * D +
                    W_N * N ;

    // ---------- Step 6: return side-channel metadata ----------
    return new PropMeta(
            D,
            N,
            score,
            lastTrialMillis,
            currentInput.size(),
            hatDists
    );
  }

  /*
  并建议在 fuzz 结束（或 EXIT_ON_CRASH）前保存一次；一个简单办法是：在 hasInput() 里即将返回 false 时做 save（但你目前 hasInput 在父类）。最小改法：在 displayStats(force=true) 或者 completeCycle() 偶尔保存一次。下面我放在 completeCycle() 里做一次：
   */
  @Override
  protected void saveCurrentInput(IntHashSet responsibilities, String why) throws IOException {
    super.saveCurrentInput(responsibilities, why);

    // only update bestDist if saved due to +prop
    if (why == null || !why.contains("+prop")) {
      return;
    }

    // fetch side-channel metadata for this input
    PropMeta meta = propMeta.get(currentInput);
    if (meta == null || meta.hatDists == null || meta.hatDists.isEmpty()) {
      return;
    }

    // update bestDist using hat distances stored in PropMeta
    for (Map.Entry<Integer, Double> e : meta.hatDists.entrySet()) {
      int mid = e.getKey();
      double hat = e.getValue();
      double old = bestDist.getOrDefault(mid, 0.0);
      if (hat > old) {
        bestDist.put(mid, hat);
      }
    }

    // persist occasionally to reduce IO
    bestDistDirtyWrites++;
    if (bestDistDirtyWrites % 50 == 0) {
      saveBestDist();
    }
  }

  // 种子选择：cycle 结束后按 propScore 排序 savedInputs（优先轮询高分种子）
  @Override
  protected void completeCycle() {
    super.completeCycle();

    // Reorder savedInputs by descending propagation score (side-channel)
    savedInputs.sort((a, b) -> {
      PropMeta ma = propMeta.get(a);
      PropMeta mb = propMeta.get(b);
      double sa = (ma == null ? 0.0 : ma.score);
      double sb = (mb == null ? 0.0 : mb.score);
      return Double.compare(sb, sa);
    });

    // keep parent index in range
    if (!savedInputs.isEmpty()) {
      currentParentInputIdx =
              Math.min(currentParentInputIdx, savedInputs.size() - 1);
    }

    // persist bestDist at cycle boundary (safe point)
    saveBestDist();

    long killedNow = deadMutants.size();
    long killedThisCycle = killedNow - lastCycleKilled;
    lastCycleKilled = killedNow;

    scheduleLog.printf(
            "%d,%d,%d,%d,%d,%s,%d\n",
            System.currentTimeMillis() / 1000,
            cyclesCompleted,
            numSavedInputs,
            numFavoredLastCycle,
            -1,
            "cycle_summary",
            killedThisCycle
    );
    scheduleLog.flush();
  }

  // 能量调度：在原 coverage 能量基础上乘距离因子
  // baseline -> coverage fraction -> favored *20。
  @Override
  protected int getTargetChildrenForParent(Input parentInput) {
    int base = super.getTargetChildrenForParent(parentInput);

    // read propagation metadata (scheme A)
    PropMeta meta = propMeta.get(parentInput);
    numScheduleDecisions++;
    double score = (meta == null ? 0.0 : meta.score);
    double pathDiffUsed = (meta == null ? 0.0 : meta.D);
    if (meta == null) {
      return base;
    }

    double mult = 1.0 + ENERGY_ALPHA * meta.D + ENERGY_BETA * meta.N;

    // avoid absurd explosion
    if (mult < 0.1) mult = 0.1;
    long scaled = (long) Math.ceil(base * mult);

    if (scaled > ENERGY_CHILD_MAX) scaled = ENERGY_CHILD_MAX;
    if (scaled < 1) scaled = 1;

    scheduleLog.printf(
            "%d,%d,%d,%d,%d,%s,%.4f,%.4f\n",
            System.currentTimeMillis() / 1000,
            cyclesCompleted,
            numSavedInputs,
            numFavoredLastCycle,
            currentParentInputIdx,
            "prop_score:",
            score,
            pathDiffUsed
    );
    return (int) scaled;
  }


  @Override
  protected void displayStats(boolean force) {
    Date now = new Date();
    long intervalTime = now.getTime() - lastRefreshTime.getTime();
    long totalTime = now.getTime() - startTime.getTime();
// 检查是否需要刷新显示
    if (intervalTime < STATS_REFRESH_TIME_PERIOD && !force) {
      return;
    }
// 计算性能指标
    double trialsPerSec = numTrials * 1000L / totalTime; // 总吞吐量：每秒执行的测试数
    long interlvalTrials = numTrials - lastNumTrials; // 间隔时期内执行的测试数
    double intervalTrialsPerSec = interlvalTrials * 1000.0 / intervalTime; //间隔期的吞吐量

    double runsPerSec = numRuns * 1000L / totalTime; // 计算总执行速度：每秒执行的变异体数
    long intervalRuns = numRuns - lastNumRuns; // 间隔期内执行的变异体数
    double intervalRunsPerSec = intervalRuns * 1000.0 / intervalTime; // 间隔期的执行速度
//   ========== 更新上次统计时数据 ==========
    lastRefreshTime = now;
    lastNumTrials = numTrials;
    lastNumRuns = numRuns;
// ========== 构建当前父输入描述 ==========
    String currentParentInputDesc;
    if (seedInputs.size() > 0 || savedInputs.isEmpty()) { // 还有种子输入或保存的输入为空
      currentParentInputDesc = "<seed>";
    } else {
      Input currentParentInput = savedInputs.get(currentParentInputIdx); // 获取当前父输入
      currentParentInputDesc = currentParentInputIdx + " ";
      // 标记是否为偏爱输入
      currentParentInputDesc += currentParentInput.isFavored() ? "(favored)" : "(not favored)";
      // 显示已生成子代数量/目标子代数量
      currentParentInputDesc += " {" + numChildrenGeneratedForCurrentParentInput +
          "/" + getTargetChildrenForParent(currentParentInput) + " mutations}";
    }
// ========== 计算覆盖率统计 ==========
    int nonZeroCount = totalCoverage.getNonZeroCount(); // 总覆盖率非零分支数
    double nonZeroFraction = nonZeroCount * 100.0 / totalCoverage.size(); // 覆盖率百分比
    int nonZeroValidCount = validCoverage.getNonZeroCount(); // 有效覆盖率非零分支数
    double nonZeroValidFraction = nonZeroValidCount * 100.0 / validCoverage.size(); // 有效覆盖率百分比
    int totalFound = getMutationInstances().size(); // 找到的总变异体数
    // ========== 控制台输出 ==========
    if (console != null) {

      if (LIBFUZZER_COMPAT_OUTPUT) {
        console.printf("#%,d\tNEW\tcov: %,d exec/s: %,d L: %,d\n", numTrials, nonZeroValidCount,
            (long) intervalTrialsPerSec, currentInput.size());
      } else if (!QUIET_MODE) {
        console.printf("\033[2J"); // 清屏
        console.printf("\033[H"); // 光标移动到左上角
        console.printf(this.getTitle() + "\n"); // 显示标题
        // 显示基本信息
        if (this.testName != null) {
          console.printf("Test name:            %s\n", this.testName);
        }
        console.printf("Results directory:    %s\n", this.outputDirectory.getAbsolutePath());
        console.printf("Elapsed time:         %s (%s)\n", millisToDuration(totalTime),
            maxDurationMillis == Long.MAX_VALUE ? "no time limit"
                : ("max " + millisToDuration(maxDurationMillis)));
        console.printf("Number of trials:     %,d\n", numTrials);
        console.printf("Number of executions: %,d\n", numRuns);
        console
            .printf("Valid inputs:         %,d (%.2f%%)\n", numValid, numValid * 100.0 / numTrials);
        console.printf("Cycles completed:     %d\n", cyclesCompleted);
        console.printf("Unique failures:      %,d\n", uniqueFailures.size());
        console.printf("Queue size:           %,d (%,d favored last cycle)\n", savedInputs.size(),
            numFavoredLastCycle);
        console.printf("Current parent input: %s\n", currentParentInputDesc);
        console.printf("Fuzzing Throughput:   %,d/sec now | %,d/sec overall\n",
            (long) intervalTrialsPerSec, (long) trialsPerSec);
        console.printf("Execution Speed:      %,d/sec now | %,d/sec overall\n",
            (long) intervalRunsPerSec, (long) runsPerSec);
        console.printf("Testing Time:         %s\n", millisToDuration(totalTime));
        console
            .printf("Mapping Time:         %s (%.2f%% of total)\n", millisToDuration(mappingTime),
                (double) mappingTime * 100.0 / (double) totalTime);
        // 变异体统计 覆盖率统计
        console.printf("Found Mutants:        %d\n", totalFound);
        console.printf("Recent Run Mutants:   %.2f (%.2f%% of total)\n", recentRun.get(),
            recentRun.get() * 100.0 / totalFound);
        console.printf("Total coverage:       %,d branches (%.2f%% of map)\n", nonZeroCount,
            nonZeroFraction);
        console.printf("Valid coverage:       %,d branches (%.2f%% of map)\n", nonZeroValidCount,
            nonZeroValidFraction);
        console.printf("Total coverage:       %,d mutants\n",
            ((MutationCoverage) totalCoverage).numCaughtMutants());
        console.printf("Available to Cover:   %,d mutants\n",
            ((MutationCoverage) totalCoverage).numSeenMutants());
      }
    }
    // ========== 写入统计文件 ==========
    /*
    时间戳, 循环数, 父输入索引, 保存输入数, 总覆盖率%, 失败数,
当前吞吐量, 有效输入数, 无效输入数, 有效覆盖率%,
总分支数, 有效分支数, 总变异体数, 杀死变异体数,
已见变异体数, 最近运行数, 测试时间, 映射时间
     */
    String plotData = String.format(
        "%d, %d, %d, %d, %d, %d, %.2f%%, %d, %d, %d, %.2f, %d, %d, %.2f%%, %d, %d, %d, %d, %d, %.2f, %d, %d",
        TimeUnit.MILLISECONDS.toSeconds(now.getTime()), cyclesCompleted, currentParentInputIdx,
        numSavedInputs, 0, 0, nonZeroFraction, uniqueFailures.size(), 0, 0, intervalTrialsPerSec,
        numValid, numTrials - numValid, nonZeroValidFraction, nonZeroCount, nonZeroValidCount,
        totalFound, deadMutants.size(), ((MutationCoverage) totalCoverage).numSeenMutants(),
        recentRun.get(), testingTime, mappingTime);
    appendLineToFile(statsFile, plotData);

    if (force && !hasInput()) {
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
