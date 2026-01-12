package cmu.pasta.mu2.diff.plugin;

import cmu.pasta.mu2.fuzz.FileMutantFilter;
import cmu.pasta.mu2.fuzz.KLeastExecutedFilter;
import cmu.pasta.mu2.fuzz.KRandomFilter;
import cmu.pasta.mu2.fuzz.MutantFilter;
import cmu.pasta.mu2.fuzz.MutationGuidance;
import cmu.pasta.mu2.instrument.Filter;
import cmu.pasta.mu2.instrument.MutationClassLoaders;
import cmu.pasta.mu2.instrument.OptLevel;
import edu.berkeley.cs.jqf.fuzz.guidance.GuidanceException;
import edu.berkeley.cs.jqf.fuzz.junit.GuidedFuzzing;
import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.junit.runner.Result;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static edu.berkeley.cs.jqf.instrument.InstrumentingClassLoader.stringsToUrls;

@Mojo(name="diff",
        requiresDependencyResolution= ResolutionScope.TEST,
        defaultPhase= LifecyclePhase.VERIFY)
public class DiffGoal extends AbstractMojo {
    @Parameter(defaultValue="${project}", required=true, readonly=true)
    MavenProject project;

    @Parameter(property="target", defaultValue="${project.build.directory}", readonly=true)
    private File target;

    /**
     * The fully-qualified name of the test class containing methods
     * to fuzz.
     * 测试类名称
     * <p>This class will be loaded using the Maven project's test
     * classpath. It must be annotated with {@code @RunWith(JQF.class)}</p>
     */
    @Parameter(property="class", required=true)
    private String testClassName;

    /**
     * The name of the method to fuzz.
     * 执行模糊测试的测试方法名称 @Fuzz注解 测试类中不能存在多个同名方法
     * <p>This method must be annotated with {@code @Fuzz}, and take
     * one or more arguments (with optional junit-quickcheck
     * annotations) whose values will be fuzzed by JQF.</p>
     *
     * <p>If more than one method of this name exists in the
     * test class or if the method is not declared
     * {@code public void}, then the fuzzer will not launch.</p>
     */
    @Parameter(property="method", required=true)
    private String testMethod;

    /**
     * Comma-separated list of FQN prefixes to forcibly include,
     * even if they match an exclude.
     *
     * <p>Typically, these will be a longer prefix than a prefix
     * in the excludes clauses.</p>
     */
    @Parameter(property="includes")
    private String includes;

    @Parameter(property="targetIncludes")
    private String targetIncludes;

    /**
     * The duration of time for which to run fuzzing.
     *
     * <p>
     * If neither this property nor {@code trials} are provided, the fuzzing
     * session is run for an unlimited time until the process is terminated by the
     * user (e.g. via kill or CTRL+C).
     * </p>
     *
     * <p>
     * Valid time durations are non-empty strings in the format [Nh][Nm][Ns], such
     * as "60s" or "2h30m".
     * </p>
     */
    @Parameter(property="time")
    private String time;

    /**
     * The number of trials for which to run fuzzing.
     *
     * <p>
     * If neither this property nor {@code time} are provided, the fuzzing
     * session is run for an unlimited time until the process is terminated by the
     * user (e.g. via kill or CTRL+C).
     * </p>
     */
    @Parameter(property="trials")
    private Long trials;

    /**
     * A number to seed the source of randomness in the fuzzing algorithm.
     *
     * <p>
     * Setting this to any value will make the result of running the same fuzzer
     * with on the same input the same. This is useful for testing the fuzzer, but
     * shouldn't be used on code attempting to find real bugs. By default, the
     * seed is chosen randomly based on system state.
     * </p>
     */
    /**
     * /**
     *      * 用于初始化模糊测试算法中随机源的种子值。
     *      *
     *      * <p>
     *      * 将此属性设置为任意值将使得在相同输入条件下运行相同的模糊测试器产生相同的结果。
     *      * 这对于测试模糊测试器本身很有用，但不应用于试图发现实际缺陷的代码测试。
     *      * 默认情况下，种子会根据系统状态随机选择。
     *      * </p>
     *      */
    @Parameter(property="randomSeed")
    private Long randomSeed;

    /**
     * The fuzzing engine.
     *///TODO
    @Parameter(property="engine", defaultValue="mutation")
    private String engine;

    /**
     * The name of the input directory containing seed files.
     *
     * <p>If not provided, then fuzzing starts with randomly generated
     * initial inputs.</p>
     */
    @Parameter(property="in")
    private String inputDirectory;

    /**
     * The name of the output directory where fuzzing results will
     * be stored.
     *
     * <p>The directory will be created inside the standard Maven
     * project build directory.</p>
     *
     * <p>If not provided, defaults to
     * <em>jqf-fuzz/${testClassName}/${$testMethod}</em>.</p>
     */
    @Parameter(property="out")
    private String outputDirectory;

    /**
     * Allows user to set optimization level for mutation-guided fuzzing.
     * Does nothing if mutation engine is not used.
     *
     * <p> If not provided, defaults to {@code EXECUTION}.
     */
    @Parameter(property="optLevel", defaultValue = "EXECUTION")
    private String optLevel;

    /**
     * Allows user to input list of filters to be used in mutation-guided fuzzing.
     *
     * <p> If not provided, defaults to no filters.
     */
    @Parameter(property="filters", defaultValue = "")
    private String filters;


    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        ClassLoader loader; // 类加载器，用于加载测试类
        MutationGuidance guidance; // 模糊测试的引导策略（使用突变引导）
        Log log = getLog(); // 获取 Maven 日志对象
        PrintStream out = log.isDebugEnabled() ? System.out : null;
        Result result; // 测试结果对象
// 解析模糊测试的时间限制
        Duration duration = null;
        if (time != null && !time.isEmpty()) {
            try {
                duration = Duration.parse("PT"+time);
            } catch (DateTimeParseException e) {
                throw new MojoExecutionException("Invalid time duration: " + time);
            }
        }
        // 设置输出目录
        if (outputDirectory == null || outputDirectory.isEmpty()) {
            outputDirectory = "fuzz-results" + File.separator + testClassName + File.separator + testMethod;
        }

        if(targetIncludes == null) {
            targetIncludes = "";
        }
        // 解析优化级别
        OptLevel ol;
        try {
            ol = OptLevel.valueOf(optLevel.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new MojoExecutionException("Invalid Mutation OptLevel!");
        }

        // Set filters to default value of empty string 设置过滤器
        if (filters == null){
            filters = "";
        }

        try {
            // 获取项目的测试类路径
            List<String> classpathElements = project.getTestClasspathElements();
            // 将类路径字符串转换为 URL 数组
            URL[] classPath = stringsToUrls(classpathElements.toArray(new String[0]));
            // 获取当前类的类加载器作为基础类加载器
            ClassLoader baseClassLoader = getClass().getClassLoader();
            // 构造目标名称：类名#方法名
            String targetName = testClassName + "#" + testMethod;
            // 初始化随机数生成器（如果指定了种子则使用，否则随机生成）
            Random rnd = randomSeed != null ? new Random(randomSeed) : new Random();
            // 设置种子文件目录（用于初始测试用例）
            File seedsDir = inputDirectory == null ? null : new File(inputDirectory);
            // 设置结果输出目录（基于 Maven 项目的 target 目录）
            File resultsDir = new File(target, outputDirectory);

            //assume MutationGuidance for the moment 突变引导式模糊测试的特殊处理
            if (includes == null) {
                throw new MojoExecutionException("Mutation-based fuzzing requires `-Dincludes`");
            }
            // 创建突变类加载器，用于在运行时修改字节码
            MutationClassLoaders mcl = new MutationClassLoaders(classPath, includes, targetIncludes, ol, baseClassLoader);
            // 获取制图（cartography）类加载器
            loader = mcl.getCartographyClassLoader();
            // 创建突变引导策略对象
            guidance = new MutationGuidance(targetName, mcl, duration, trials, resultsDir, seedsDir, rnd);
            // Parse string of filters for list of MutantFilters and add to guidance 解析过滤器字符串并添加到引导策略中
            guidance.addFilters(parseFilters(filters, guidance));
        } catch (DependencyResolutionRequiredException | MalformedURLException e) {
            throw new MojoExecutionException("Could not get project classpath", e);
        } catch (FileNotFoundException e) {
            throw new MojoExecutionException("File not found", e);
        } catch (IOException e) {
            throw new MojoExecutionException("I/O error", e);
        }
        // 执行模糊测试
        try {
            result = GuidedFuzzing.run(testClassName, testMethod, loader, guidance, out);
        } catch (ClassNotFoundException e) {
            throw new MojoExecutionException("Could not load test class", e);
        } catch (IllegalArgumentException e) {
            throw new MojoExecutionException("Bad request", e);
        } catch (RuntimeException e) {
            throw new MojoExecutionException("Internal error", e);
        }

        if (!result.wasSuccessful()) {
            Throwable e = result.getFailures().get(0).getException();
            e.printStackTrace();
            if (result.getFailureCount() == 1) {
                if (e instanceof GuidanceException) {
                    throw new MojoExecutionException("Internal error", e);
                }
            }
            throw new MojoFailureException(String.format("Fuzzing resulted in the test failing on " +
                            "%d input(s). Possible bugs found. " +
                            "Use mvn jqf:repro to reproduce failing test cases. ",
                    result.getFailureCount()) +
                    "Sample exception included with this message.", e);
        }
    }

    private List<MutantFilter> parseFilters (String filterSpec, MutationGuidance guidance) throws MojoExecutionException{
        // Initialize empty list of filters
        List<MutantFilter> filterList = new ArrayList<>();
        int i = 0;
        char[] filterChars = filters.toCharArray();
        String current = "";
        Filter f;
        int len = filterChars.length;

        // Parse input string (of format "filter1:arg1,arg2,...,filter2:arg1,arg2,...") to create list of filters
        while(i < len){
            char c = filterChars[i];
            if (c == ':') {
                try {
                    f = Filter.valueOf(current.toUpperCase());
                } catch (IllegalArgumentException e) {
                    throw new MojoExecutionException("Invalid Mutation Filter!");
                }
                if (f == Filter.KRANDOM || f == Filter.KLEASTEXEC){
                    
                    i++;
                    String arg = "";
                    while (i < len && filterChars[i] != ','){
                        arg += filterChars[i];
                        i ++;
                    }

                    if (arg.charAt(arg.length()-1) == '%'){
                        int k = getPercent(arg);
                        filterList.add(f == Filter.KRANDOM ? new KRandomFilter(k, true, guidance) : new KLeastExecutedFilter(k, true, guidance));
                    }    
                    else{
                        int k = getNum(arg);
                        filterList.add(f == Filter.KRANDOM ? new KRandomFilter(k): new KLeastExecutedFilter(k));
                    }
                } else if (f == Filter.FILE) {

                    i++;
                    String arg = "";
                    while (i < len && filterChars[i] != ','){
                        arg += filterChars[i];
                        i ++;
                    }
                    try {
                        filterList.add(new FileMutantFilter(arg));
                    } catch (FileNotFoundException e) {
                        throw new MojoExecutionException("Invalid Mutation Filter Argument(s)!");
                    }
                }
                current = "";
            } else {
                current += c;
            }
            i += 1;
        }

        return filterList;
    }

    private int getPercent(String arg) throws MojoExecutionException{
        int k;
        try {
            k = Integer.parseInt(arg.substring(0, arg.length()-1));
        } catch (NumberFormatException e) {
            throw new MojoExecutionException("Invalid Mutation Filter Argument(s)!");
        }
        if (k > 100 || k < 0){
            throw new MojoExecutionException("Invalid Percentage for Random Filter");
        }
        return k;
    }

    private int getNum(String arg) throws MojoExecutionException{
        int k;
        try {
            k = Integer.parseInt(arg);
        } catch (NumberFormatException e) {
            throw new MojoExecutionException("Invalid Mutation Filter Argument(s)!");
        }
        return k;
    }
}
