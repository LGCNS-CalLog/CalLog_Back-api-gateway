package com.callog.callog_api_gateway.filter;

import com.callog.callog_api_gateway.security.UserPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.function.ServerRequest;

import java.util.function.Function;

/**
 * 1. SecurityContext에서 인증된 사용자 정보 가져오기
 * 2. 사용자 정보를 HTTP 헤더로 변환
 * 3. 다음 서비스(User Service)로 전달할 요청에 헤더 추가
 *
 * 추가되는 헤더들:
 * - X-Auth-User-Id: 로그인한 사용자의 userId (Long 타입)
 * - X-Auth-Username: 로그인한 사용자의 username
 * - X-Client-Device: 클라이언트 디바이스 타입 (WEB, MOBILE 등)
 * - X-Client-Address: 클라이언트 IP 주소
 */
public class AuthenticationHeaderFilterFunction {

    public static Function<ServerRequest, ServerRequest> addHeader() {
        return request -> {
            ServerRequest.Builder requestBuilder = ServerRequest.from(request);
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            if (principal instanceof UserPrincipal userPrincipal) {
                // ✅ JWT 인증이 성공한 경우 - 사용자 정보 헤더 추가
                requestBuilder.header("X-Auth-User-Id", userPrincipal.getUserId().toString());
                requestBuilder.header("X-Auth-Username", userPrincipal.getUsername());
            }

            String remoteAddr = getClientIpAddress(request);
            requestBuilder.header("X-Client-Address", remoteAddr);

            String device = determineDeviceType(request);
            requestBuilder.header("X-Client-Device", device);

            return requestBuilder.build();
        };
    }

    private static String getClientIpAddress(ServerRequest request) {
        return request.servletRequest().getRemoteAddr();
    }

    private static String determineDeviceType(ServerRequest request) {
        String userAgent = request.headers().firstHeader("User-Agent");

        if (userAgent == null) {
            return "WEB";
        }

        userAgent = userAgent.toLowerCase();

        if (userAgent.contains("mobile") || userAgent.contains("android") || userAgent.contains("iphone")) {
            return "MOBILE";
        } else if (userAgent.contains("tablet") || userAgent.contains("ipad")) {
            return "TABLET";
        } else {
            return "WEB";
        }
    }
}