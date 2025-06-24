package com.callog.callog_api_gateway.config.jwt;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(value = "jwt", ignoreUnknownFields = true)
@Getter
@Setter
public class JwtConfigProperties {
    // JWT 설정 정보를 담은 객체
    private String header = "Authorization";
    private String secretKey;
    private Integer expiresIn;        // 액세스 토큰 만료시간
    private Integer mobileExpiresIn;  // 모바일 리프레시 토큰 만료시간
    private Integer tabletExpiresIn;

    // 🔄 getHeader() 메서드가 없어서 JwtTokenValidator에서 오류 발생할 수 있음
    public String getHeader() {
        return header != null ? header : "Authorization";
    }

}