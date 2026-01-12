package cmu.pasta.mu2.diff.guidance;

import cmu.pasta.mu2.instrument.MutationInstance;
import cmu.pasta.mu2.fuzz.MutationRunInfo;
import cmu.pasta.mu2.instrument.MutationSnoop;
import cmu.pasta.mu2.instrument.OptLevel;
import cmu.pasta.mu2.util.ArraySet;
import cmu.pasta.mu2.instrument.MutationClassLoaders;
import edu.berkeley.cs.jqf.fuzz.difffuzz.DiffException;
import edu.berkeley.cs.jqf.fuzz.difffuzz.DiffFuzzReproGuidance;
import edu.berkeley.cs.jqf.fuzz.difffuzz.Outcome;
import edu.berkeley.cs.jqf.fuzz.difffuzz.Serializer;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.instrument.InstrumentationException;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.TestClass;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.ArrayList;
import java.util.function.BiConsumer;

/**
 * to avoid the problem of the generator type registry not updating for each ClassLoader
 */
public class DiffMutationReproGuidance extends DiffFuzzReproGuidance {
    public List<Outcome> cclOutcomes; //原始程序执行结果列表

    /**
     *  mutation analysis results for each MutationInstance
     * paired with the index of the outcome that killed the mutant
     */

    private final MutationClassLoaders MCLs; // 变异类加载器集合
    private int ind; //当前输入序号

    /**
     * The mutants killed so far
     */
    public final ArraySet deadMutants = new ArraySet(); // 已杀死的变异体集合

    /**
     * Current optimization level
     */
    private final OptLevel optLevel; // 优化级别 用于PIE模型

    /**
     * The set of mutants to execute for a given trial.
     *
     * This is used when the optLevel is set to something higher than NONE,
     * in order to selectively choose which mutants are interesting for a given
     * input. This may include already killed mutants; those are skipped separately.
     *
     * This set must be reset/cleared before execution of every new input.
     */
    private static ArraySet runMutants = new ArraySet(); // 当前输入需要执行的变异体集合
    private static Object infectedValue;
    private static boolean infectedValueStored;

    private File reportFile;

    public DiffMutationReproGuidance(File inputFile, File traceDir, MutationClassLoaders mcls, File resultsDir) throws IOException {
        super(inputFile, traceDir);
        cclOutcomes = new ArrayList<>();
        MCLs = mcls;
        ind = -1;

        reportFile = new File(resultsDir, "mutate-repro-out.txt");
        this.optLevel = MCLs.getCartographyClassLoader().getOptLevel();
    }

    @Override
    public void run(TestClass testClass, FrameworkMethod method, Object[] args) throws Throwable {
        runMutants.reset();
        // 设置变异执行回调，记录哪些变异体被执行
        MutationSnoop.setMutantExecutionCallback(m -> runMutants.add(m.id));
        // 设置感染回调，检测值是否被感染
        BiConsumer<MutationInstance, Object> infectionCallback = (m, value) -> {
            if (!infectedValueStored) {
                infectedValue = value;
                infectedValueStored = true;
            } else {
                // 比较原始值和变异值
                if (infectedValue == null) {
                    if (value != null) {
                        runMutants.add(m.id); // 值被改变，需要执行
                    }
                } else if (!infectedValue.equals(value)) {
                    runMutants.add(m.id); // 值被改变，需要执行
                }
                infectedValueStored = false;
            }
        };
        MutationSnoop.setMutantInfectionCallback(infectionCallback);

        recentOutcomes.clear();
        cmpTo = null;

        ind++;

        // run CCL 使用原始类加载器执行原始程序
        try {
            super.run(testClass, method, args);
        } catch(InstrumentationException e) {
            throw new GuidanceException(e);
        } catch (GuidanceException e) {
            throw e;
        } catch (Throwable e) {}

        System.out.println("CCL Outcome for input " + ind + ": " + recentOutcomes.get(0));
        try (PrintWriter pw = new PrintWriter(new FileOutputStream(reportFile, true))) {
            pw.printf("CCL Outcome for input %d: %s\n", ind, recentOutcomes.get(0).toString());
        }

        // set up info
        cmpTo = new ArrayList<>(recentOutcomes);
        cclOutcomes.add(cmpTo.get(0));
        byte[] argBytes = Serializer.serialize(args);
        recentOutcomes.clear();

        for (MutationInstance mutationInstance : MCLs.getCartographyClassLoader().getMutationInstances()) {
            if (deadMutants.contains(mutationInstance.id)) {
                continue;
            }
            // 如果启用优化，只执行相关变异体
            if (optLevel != OptLevel.NONE  &&
                    !runMutants.contains(mutationInstance.id)) {
                continue;
            }
            // 准备变异执行信息
            MutationRunInfo mri = new MutationRunInfo(MCLs, mutationInstance, testClass, argBytes, args, method);
            mutationInstance.resetTimer();

            // run with MCL 执行变异程序
            System.out.println("Running Mutant " + mutationInstance);
            try (PrintWriter pw = new PrintWriter(new FileOutputStream(reportFile, true))) {
                pw.printf("Running Mutant %s\n", mutationInstance.toString());
            }

            try {
                super.run(new TestClass(mri.clazz), mri.method, mri.args);
            } catch (DiffException e) {
                // 变异体被杀死
                deadMutants.add(mutationInstance.id);
                System.out.println("FAILURE: killed by input " + ind + ": " + e);
                try (PrintWriter pw = new PrintWriter(new FileOutputStream(reportFile, true))) {
                    pw.printf("FAILURE: killed by input %d: %s\n", ind, e.toString());
                }
            } catch(InstrumentationException e) {
                throw new GuidanceException(e);
            } catch (GuidanceException e) {
                throw e;
            } catch (Throwable e) {}

            recentOutcomes.clear();
        }
        if(cclOutcomes.get(cclOutcomes.size() - 1).thrown != null) throw cclOutcomes.get(cclOutcomes.size() - 1).thrown;
    }

}
