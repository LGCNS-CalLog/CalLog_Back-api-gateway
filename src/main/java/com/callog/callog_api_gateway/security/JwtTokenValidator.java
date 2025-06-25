package com.callog.callog_api_gateway.security;

import com.callog.callog_api_gateway.config.jwt.JwtConfigProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenValidator {
    private final JwtConfigProperties configProperties;
    private volatile SecretKey secretKey;


    //user service랑 동일한 비밀키 생성
    private SecretKey getSecretKey() {
        if (secretKey == null) {
            synchronized (this) {
                if (secretKey == null) {
                    secretKey = Keys.hmacShaKeyFor(configProperties.getSecretKey().getBytes());
                }
            }
        }
        return secretKey;
    }

    // JWT 토큰 검증, authentication 객체 생성
    public JwtAuthentication validateToken(String token) {
        // 1. JWT 토큰을 파싱해서 claims 추출
        final Claims claims = this.verifyAndGetClaims(token);
        if(claims == null) {
            return null;
        }
        // 2. 만료시간 체크
        Date expirationDate = claims.getExpiration();
        if (expirationDate == null || expirationDate.before(new Date())) {
            log.warn("만료된 토큰입니다.");
            return null;
        }

        //3. user Service 에서 설정한 클레임들과 동일하게 추출
        String username = claims.get("username", String.class);
        Long userId = claims.get("userId",Long.class);
        String tokenType = claims.get("tokenType", String.class);

        //4. access 토큰만 허용
        if (!"access".equals(tokenType)) {
            return null;
        }
        // 5. 로그아웃된 토큰 체크
        Boolean loggedOut = claims.get("loggedOut", Boolean.class);
        if(Boolean.TRUE.equals(loggedOut)) {
            return  null;
        }
        //6. 사용자명 유효성 체크
        if(username == null || username.trim().isEmpty()) {
            return null;
        }
        if(userId == null) {
            return null;
        }

        // 7. 모든 검증 통과, Authentication 객체 생성
        UserPrincipal principal = new UserPrincipal(username,userId);
        return new JwtAuthentication(principal, token, getGrantedAuthorities("USER"));

    }

    // JWT 토큰 파싱하고 claims 추출
    private Claims verifyAndGetClaims(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            log.warn("JWT 토큰 검증 실패: {}", e.getMessage());
            claims = null;
        }
        return claims;
    }

    //
    private List<GrantedAuthority> getGrantedAuthorities(String role) {
        ArrayList<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        if (role != null) {
            grantedAuthorities.add(new SimpleGrantedAuthority(role));
        }
        return grantedAuthorities;
    }
    public String getToken(HttpServletRequest request) {
        String authHeader = getAuthHeaderFromHeader(request);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);  // "Bearer " 제거해서 순수 토큰만 반환
        }
        return null;
    }
    private String getAuthHeaderFromHeader(HttpServletRequest request) {
        return request.getHeader(configProperties.getHeader());  // "Authorization" 헤더 값
    }
}