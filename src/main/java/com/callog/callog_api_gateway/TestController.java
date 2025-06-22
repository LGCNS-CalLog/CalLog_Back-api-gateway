package com.callog.callog_api_gateway;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    // api 테스트
    @GetMapping(value = "/test")
    public String test() {
        String response = "테스트입니다.";
        return response;
    }
}
