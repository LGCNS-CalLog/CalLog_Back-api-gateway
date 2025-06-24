package com.callog.callog_api_gateway.test;

import com.callog.callog_api_gateway.security.JwtAuthentication;
import com.callog.callog_api_gateway.security.JwtTokenValidator;
import com.callog.callog_api_gateway.security.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/gateway/debug")
@RequiredArgsConstructor
public class GatewayDebugController {

    private final JwtTokenValidator jwtTokenValidator;

    /**
     * 🔍 Gateway 자체 상태 확인
     */
    @GetMapping("/health")
    public ResponseEntity<?> gatewayHealth() {
        return ResponseEntity.ok(Map.of(
                "status", "UP",
                "timestamp", LocalDateTime.now(),
                "service", "API Gateway",
                "message", "Gateway가 정상 동작 중입니다"
        ));
    }

    /**
     * 🧪 JWT 토큰 검증 테스트 (핵심!)
     */
    @GetMapping("/jwt-test")
    public ResponseEntity<?> jwtTest(HttpServletRequest request) {
        Map<String, Object> result = new HashMap<>();

        // 1. 토큰 추출 테스트
        String token = jwtTokenValidator.getToken(request);
        result.put("step1_tokenExtraction", Map.of(
                "hasToken", token != null,
                "tokenLength", token != null ? token.length() : 0,
                "tokenPreview", token != null ? token.substring(0, Math.min(50, token.length())) + "..." : "없음"
        ));

        if (token != null) {
            // 2. 토큰 검증 테스트
            JwtAuthentication auth = jwtTokenValidator.validateToken(token);
            result.put("step2_tokenValidation", Map.of(
                    "isValid", auth != null,
                    "hasAuthorities", auth != null && !auth.getAuthorities().isEmpty()
            ));

            if (auth != null) {
                UserPrincipal principal = auth.getPrincipal();

                // 3. 사용자 정보 추출 테스트
                result.put("step3_userExtraction", Map.of(
                        "username", principal.getUsername(),
                        "userId", principal.getUserId(),
                        "userIdType", principal.getUserId() != null ? principal.getUserId().getClass().getSimpleName() : "null",
                        "hasUsername", principal.hasName(),
                        "hasUserId", principal.hasUserId()
                ));

                // 4. 헤더 변환 시뮬레이션 (실제 필터 로직)
                Map<String, String> simulatedHeaders = new HashMap<>();
                if (principal.getUserId() != null) {
                    simulatedHeaders.put("X-Auth-User-Id", principal.getUserId().toString());
                }
                if (principal.getUsername() != null) {
                    simulatedHeaders.put("X-Auth-Username", principal.getUsername());
                }
                simulatedHeaders.put("X-Client-Device", "WEB");
                simulatedHeaders.put("X-Client-Address", request.getRemoteAddr());

                result.put("step4_headerSimulation", Map.of(
                        "headers", simulatedHeaders,
                        "userIdAsString", principal.getUserId() != null ? principal.getUserId().toString() : "null",
                        "canConvertToLong", testLongConversion(principal.getUserId())
                ));
            }
        }

        // 5. SecurityContext 확인
        Authentication contextAuth = SecurityContextHolder.getContext().getAuthentication();
        result.put("step5_securityContext", Map.of(
                "hasAuthentication", contextAuth != null,
                "isAuthenticated", contextAuth != null && contextAuth.isAuthenticated(),
                "principalType", contextAuth != null && contextAuth.getPrincipal() != null ?
                        contextAuth.getPrincipal().getClass().getSimpleName() : "null"
        ));

        return ResponseEntity.ok(result);
    }

    /**
     * 🎯 필터 동작 시뮬레이션 (AuthenticationHeaderFilterFunction 로직 테스트)
     */
    @GetMapping("/filter-simulation")
    public ResponseEntity<?> filterSimulation(HttpServletRequest request, Authentication auth) {
        Map<String, Object> result = new HashMap<>();

        // 현재 인증 상태 확인
        Object principal = auth != null ? auth.getPrincipal() : null;

        if (principal instanceof UserPrincipal userPrincipal) {
            // ✅ 성공적인 경우 시뮬레이션
            Map<String, String> wouldAddHeaders = new HashMap<>();

            Long userId = userPrincipal.getUserId();
            String username = userPrincipal.getUsername();

            if (userId != null) {
                wouldAddHeaders.put("X-Auth-User-Id", userId.toString());
            }
            if (username != null) {
                wouldAddHeaders.put("X-Auth-Username", username);
            }
            wouldAddHeaders.put("X-Client-Device", "WEB");
            wouldAddHeaders.put("X-Client-Address", request.getRemoteAddr());

            result.put("filterWouldWork", true);
            result.put("headersToAdd", wouldAddHeaders);
            result.put("principalType", "UserPrincipal");
            result.put("message", "✅ 필터가 정상적으로 헤더를 추가할 것입니다");

        } else {
            result.put("filterWouldWork", false);
            result.put("principalType", principal != null ? principal.getClass().getSimpleName() : "null");
            result.put("message", "❌ 인증되지 않았거나 잘못된 Principal 타입입니다");
        }

        return ResponseEntity.ok(result);
    }

    /**
     * 🔧 JWT 설정 확인
     */
    @GetMapping("/config-check")
    public ResponseEntity<?> configCheck() {
        Map<String, Object> result = new HashMap<>();

        try {
            // JWT 설정 테스트를 위해 더미 토큰으로 검증 시도
            result.put("jwtValidatorExists", jwtTokenValidator != null);
            result.put("message", "JWT Validator가 정상적으로 주입되었습니다");
            result.put("timestamp", LocalDateTime.now());

        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("message", "JWT 설정에 문제가 있습니다");
        }

        return ResponseEntity.ok(result);
    }

    /**
     * 🧪 Long 타입 변환 테스트 헬퍼 메서드
     */
    private Map<String, Object> testLongConversion(Long userId) {
        Map<String, Object> conversionTest = new HashMap<>();

        if (userId == null) {
            conversionTest.put("success", false);
            conversionTest.put("error", "userId가 null입니다");
            return conversionTest;
        }

        try {
            String stringValue = userId.toString();
            Long convertedBack = Long.parseLong(stringValue);

            conversionTest.put("success", true);
            conversionTest.put("original", userId);
            conversionTest.put("stringForm", stringValue);
            conversionTest.put("convertedBack", convertedBack);
            conversionTest.put("isEqual", userId.equals(convertedBack));

        } catch (NumberFormatException e) {
            conversionTest.put("success", false);
            conversionTest.put("error", e.getMessage());
        }

        return conversionTest;
    }
}