package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BatchItemResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 批量检测：条目数、并发上限、单条超时受控，单条失败互不影响。
 */
@Service
public class BatchDetectionService {

    private final DetectionService detectionService;
    private final DetectionProperties properties;

    public BatchDetectionService(DetectionService detectionService, DetectionProperties properties) {
        this.detectionService = detectionService;
        this.properties = properties;
    }

    public List<BatchItemResult> detectBatch(List<String> inputs) {
        return detectBatch(inputs, System.currentTimeMillis());
    }

    public List<BatchItemResult> detectBatch(List<String> inputs, long nowMillis) {
        if (inputs == null) {
            throw new IllegalArgumentException("批量输入不能为空");
        }
        if (inputs.size() > properties.getMaxBatchSize()) {
            throw new IllegalArgumentException(
                    "批量条目数 " + inputs.size() + " 超过上限 " + properties.getMaxBatchSize());
        }
        ExecutorService executor = newExecutor();
        List<BatchItemResult> results = new java.util.ArrayList<>(inputs.size());
        try {
            List<Future<BatchItemResult>> futures = new java.util.ArrayList<>(inputs.size());
            for (int i = 0; i < inputs.size(); i++) {
                final int index = i;
                final String input = inputs.get(i);
                futures.add(executor.submit(() -> runWithTimeout(input, nowMillis, index)));
            }
            for (Future<BatchItemResult> future : futures) {
                try {
                    results.add(future.get());
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("批量检测被中断", ex);
                } catch (ExecutionException ex) {
                    throw new IllegalStateException("批量检测异常", ex);
                }
            }
        } finally {
            executor.shutdownNow();
        }
        results.sort((a, b) -> Integer.compare(a.index(), b.index()));
        return results;
    }

    ExecutorService newExecutor() {
        int parallelism = Math.max(1, properties.getBatchConcurrency());
        return Executors.newFixedThreadPool(parallelism, runnable -> {
            Thread thread = new Thread(runnable, "guard-batch-detect");
            thread.setDaemon(true);
            return thread;
        });
    }

    private BatchItemResult runWithTimeout(String input, long nowMillis, int index) {
        ExecutorService single = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "guard-item-detect");
            thread.setDaemon(true);
            return thread;
        });
        Future<Verdict> future = single.submit(() -> detectionService.detect(input, nowMillis));
        try {
            Verdict verdict = future.get(properties.getPerItemTimeoutMillis(), TimeUnit.MILLISECONDS);
            return new BatchItemResult(index, input, verdict, null);
        } catch (TimeoutException ex) {
            future.cancel(true);
            return new BatchItemResult(index, input, null, "检测超时");
        } catch (Exception ex) {
            Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
            return new BatchItemResult(index, input, null, cause.getMessage());
        } finally {
            single.shutdownNow();
        }
    }
}
