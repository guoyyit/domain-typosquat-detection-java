package com.github.guoyyit.domaintyposquatdetectionjava.web;

/**
 * 可映射为 HTTP 4xx 的业务异常。
 */
public class ApiException extends RuntimeException {

    private final int status;

    public ApiException(int status, String message) {
        super(message);
        this.status = status;
    }

    public static ApiException badRequest(String message) {
        return new ApiException(400, message);
    }

    public static ApiException notFound(String message) {
        return new ApiException(404, message);
    }

    public int getStatus() {
        return status;
    }
}
