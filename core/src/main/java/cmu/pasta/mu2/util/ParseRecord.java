package cmu.pasta.mu2.util;

public class ParseRecord {

    public String caseId;

    public String inputBase64;

    public String inputPreview; // UI展示

    public String status; // SUCCESS / INVALID / FAILURE

    public String normalizedOutput;

    public String exceptionType;

    public ParseRecord() {}

    public static ParseRecord success(String caseId,
                                      String inputBase64,
                                      String inputPreview,
                                      String normalizedOutput) {
        ParseRecord r = new ParseRecord();
        r.caseId = caseId;
        r.inputBase64 = inputBase64;
        r.inputPreview = inputPreview;
        r.status = "SUCCESS";
        r.normalizedOutput = normalizedOutput;
        r.exceptionType = null;
        return r;
    }

    public static ParseRecord invalid(String caseId,
                                      String inputBase64,
                                      String inputPreview,
                                      String exceptionType) {
        ParseRecord r = new ParseRecord();
        r.caseId = caseId;
        r.inputBase64 = inputBase64;
        r.inputPreview = inputPreview;
        r.status = "INVALID";
        r.normalizedOutput = null;
        r.exceptionType = exceptionType;
        return r;
    }

    public static ParseRecord failure(String caseId,
                                      String inputBase64,
                                      String inputPreview,
                                      String exceptionType) {
        ParseRecord r = new ParseRecord();
        r.caseId = caseId;
        r.inputBase64 = inputBase64;
        r.inputPreview = inputPreview;
        r.status = "FAILURE";
        r.normalizedOutput = null;
        r.exceptionType = exceptionType;
        return r;
    }
}