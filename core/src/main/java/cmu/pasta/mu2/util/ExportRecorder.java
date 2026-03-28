package cmu.pasta.mu2.util;

import com.alibaba.fastjson2.JSON;

import java.io.*;
import java.nio.charset.StandardCharsets;

public final class ExportRecorder {

    private static final Object LOCK = new Object();

    private ExportRecorder() {}

    public static void record(ParseRecord record) {
        String outputPath = System.getProperty("jqf.repro.exportRecords");
        if (outputPath == null || outputPath.isEmpty()) {
            return;
        }

        File file = new File(outputPath);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new RuntimeException("Failed to create export directory: " + parent);
        }

        synchronized (LOCK) {
            try (Writer writer = new OutputStreamWriter(
                    new FileOutputStream(file, true), StandardCharsets.UTF_8)) {

                // 使用 fastjson2 序列化
                writer.write(JSON.toJSONString(record));

                writer.write(System.lineSeparator());

            } catch (IOException e) {
                throw new RuntimeException("Failed to write export record: " + file, e);
            }
        }
    }
}