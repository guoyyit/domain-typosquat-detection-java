package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 批量检测中单个条目的结果，与输入下标一一对应。
 * 单条失败只标记 error，不影响其余条目。
 */
public record BatchItemResult(
        int index,
        String input,
        DetectionResult result,
        String error
) {

    public static BatchItemResult ok(int index, String input, DetectionResult result) {
        return new BatchItemResult(index, input, result, null);
    }

    public static BatchItemResult failure(int index, String input, String error) {
        return new BatchItemResult(index, input, null, error);
    }
}
