package cmu.pasta.mu2.examples.gson;

import edu.berkeley.cs.jqf.fuzz.Fuzz;
import edu.berkeley.cs.jqf.fuzz.JQF;
import edu.berkeley.cs.jqf.fuzz.difffuzz.Comparison;
import edu.berkeley.cs.jqf.fuzz.difffuzz.DiffFuzz;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONWriter;
import edu.berkeley.cs.jqf.fuzz.repro.ReproCaseContext;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import org.apache.commons.lang3.StringEscapeUtils;
import cmu.pasta.mu2.util.ExportRecorder;
import cmu.pasta.mu2.util.ParseRecord;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;
import com.pholser.junit.quickcheck.From;
import edu.berkeley.cs.jqf.examples.common.AsciiStringGenerator;
import org.junit.Assume;
import org.junit.runner.RunWith;

@RunWith(JQF.class)
public class JsonTest {

    private GsonBuilder builder = new GsonBuilder();
    private Gson gson = builder.setLenient().create();

    @DiffFuzz
    public Object testJSONParser(@From(AsciiStringGenerator.class) String input) {
        Object out = null;
        try {
            out = gson.fromJson(input, Object.class);
        } catch (JsonSyntaxException e) {
            Assume.assumeNoException(e);
        } catch (JsonIOException e) {
            Assume.assumeNoException(e);
        }
        return out;
    }

    @Fuzz(repro="${repro}")
    public void fuzzJSONParser(@From(AsciiStringGenerator.class) String input) {
        Object out = null;
        try {
            out = gson.fromJson(input, Object.class);
        } catch (JsonSyntaxException e) {
            Assume.assumeNoException(e);
        } catch (JsonIOException e) {
            Assume.assumeNoException(e);
        }
    }

    @Fuzz(repro="${repro}")
    public void fuzzJSONParserInputOut(@From(AsciiStringGenerator.class) String input) {
        String caseId = ReproCaseContext.getCurrentCaseId();
        if (caseId == null) {
            caseId = "unknown";
        }

        String inputBase64 = Base64.getEncoder()
                .encodeToString(input.getBytes(StandardCharsets.UTF_8));
        String preview = StringEscapeUtils.escapeJava(input);

        try {
            Object out = gson.fromJson(input, Object.class);

            // 使用 fastjson2 生成规范化输出
            String normalizedOutput = JSON.toJSONString(out, JSONWriter.Feature.MapSortField);

            ExportRecorder.record(ParseRecord.success(
                    caseId,
                    inputBase64,
                    preview,
                    normalizedOutput
            ));

        } catch (JsonSyntaxException e) {
            ExportRecorder.record(ParseRecord.invalid(
                    caseId,
                    inputBase64,
                    preview,
                    e.getClass().getName()
            ));
            Assume.assumeNoException(e);

        } catch (JsonIOException e) {
            ExportRecorder.record(ParseRecord.invalid(
                    caseId,
                    inputBase64,
                    preview,
                    e.getClass().getName()
            ));
            Assume.assumeNoException(e);

        } catch (Throwable t) {
            ExportRecorder.record(ParseRecord.failure(
                    caseId,
                    inputBase64,
                    preview,
                    t.getClass().getName()
            ));
            throw t;
        }
    }

    @DiffFuzz(cmp = "noncompare")
    public Object testJSONParserNoncompare(@From(AsciiStringGenerator.class) String input) {
        Object out = null;
        try {
            out = gson.fromJson(input, Object.class);
        } catch (JsonSyntaxException e) {
            Assume.assumeNoException(e);
        } catch (JsonIOException e) {
            Assume.assumeNoException(e);
        }
        return out;
    }

    @Comparison
    public static Boolean noncompare(Object o1, Object o2) {
        return true;
    }

}
