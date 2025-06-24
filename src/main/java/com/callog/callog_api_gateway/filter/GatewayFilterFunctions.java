package com.callog.callog_api_gateway.filter;

import org.springframework.cloud.gateway.server.mvc.common.Shortcut;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.ServerResponse;
import static org.springframework.web.servlet.function.HandlerFilterFunction.ofRequestProcessor;

/**
 * 🔧 Spring Cloud Gateway MVC의 필터 함수들을 정의하는 인터페이스
 *
 * @Shortcut 어노테이션:
 * - YAML 설정에서 간단한 이름으로 필터를 사용할 수 있게 해줌
 * - 예: filters: - AddAuthenticationHeader
 *
 * ofRequestProcessor():
 * - 요청을 변경하는 필터를 만들 때 사용
 * - 응답을 변경하려면 ofResponseProcessor() 사용
 */
public interface GatewayFilterFunctions {
    @Shortcut
    static HandlerFilterFunction<ServerResponse, ServerResponse> addAuthenticationHeader() {
        return ofRequestProcessor(AuthenticationHeaderFilterFunction.addHeader());
    }

}