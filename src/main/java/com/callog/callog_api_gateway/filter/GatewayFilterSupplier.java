package com.callog.callog_api_gateway.filter;

import org.springframework.cloud.gateway.server.mvc.filter.SimpleFilterSupplier;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayFilterSupplier extends SimpleFilterSupplier {

    public GatewayFilterSupplier() {
        // GatewayFilterFunctions 클래스의 @Shortcut 어노테이션이 붙은
        // 모든 static 메서드들을 필터로 등록
        super(GatewayFilterFunctions.class);
    }
}