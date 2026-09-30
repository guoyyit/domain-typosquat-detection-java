package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BatchItemResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.DetectionResult;
import com.github.guoyyit.domaintyposquatdetectionjava.web.ApiException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 批量检测：
 * 单批条目数受 maxBatchSize 限制；并发度由固定大小线程池 + 信号量双重约束；
 * 每条检测受 timeoutMillis 约束；任一条失败/超时只在对应下标返回 error，
 * 不影响其余条目，且结果顺序与输入完全一致。
 */
@Service
public class BatchDetectionService {

    private final DetectionProperties properties;
    private final DetectionService detectionService;
    private final ExecutorService executor;

    public BatchDetectionService(DetectionProperties properties, DetectionService detectionService) {
        this.properties = properties;
        this.detectionService = detectionService;
        int concurrency = Math.max(1, properties.getBatch().getConcurrency());
        this.executor = Executors.newFixedThreadPool(concurrency, runnable -> {
            Thread thread = new Thread(runnable, "batch-detection");
            thread.setDaemon(true);
            return thread;
        });
    }

    public List<BatchItemResult> detectBatch(List<String> inputs) {
        if (inputs == null) {
            throw ApiException.badRequest("domains are required");
        }
        int maxBatchSize = properties.getBatch().getMaxBatchSize();
        if (inputs.size() > maxBatchSize) {
            throw new ApiException(413,
                    "batch size " + inputs.size() + " exceeds max " + maxBatchSize);
        }

        List<BatchItemResult> results = new ArrayList<>(inputs.size());
        if (inputs.isEmpty()) {
            return results;
        }

        int concurrency = Math.max(1, properties.getBatch().getConcurrency());
        Semaphore permits = new Semaphore(concurrency);
        List<Future<BatchItemResult>> futures = new ArrayList<>(inputs.size());
        for (int i = 0; i < inputs.size(); i++) {
            final int index = i;
            final String input = inputs.get(i);
            futures.add(executor.submit(() -> detectOne(permits, index, input)));
        }

        for (int i = 0; i < futures.size(); i++) {
            results.add(collectOne(futures.get(i), i, inputs.get(i)));
        }
        return results;
    }

    private BatchItemResult detectOne(Semaphore permits, int index, String input)
            throws InterruptedException {
        permits.acquire();
        try {
            DetectionResult result = detectionService.detect(input);
            return BatchItemResult.ok(index, input, result);
        } finally {
            permits.release();
        }
    }

    private BatchItemResult collectOne(Future<BatchItemResult> future, int index, String input) {
        try {
            return future.get(properties.getBatch().getTimeoutMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            return BatchItemResult.failure(index, input, "detection timeout");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return BatchItemResult.failure(index, input, "batch interrupted");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            return BatchItemResult.failure(index, input,
                    cause.getClass().getSimpleName() + ": " + cause.getMessage());
        }
    }
}
