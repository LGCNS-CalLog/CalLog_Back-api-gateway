package com.callog.callog_api_gateway.common.exception;

import org.springframework.http.HttpStatus;

public interface ErrorCodeInterface {
    String getCode();
    String getMessage();
    HttpStatus getStatus();
}
