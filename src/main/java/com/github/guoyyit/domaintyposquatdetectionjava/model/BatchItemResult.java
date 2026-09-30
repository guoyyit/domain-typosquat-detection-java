package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 批量检测中单条输入的结果，与输入下标一一对应。
 *
 * @param index   输入下标
 * @param input   原始输入
 * @param verdict 判定结果；失败时为 {@code null}
 * @param error   失败原因；成功时为 {@code null}
 */
public record BatchItemResult(
        int index,
        String input,
        Verdict verdict,
        String error
) {
}
