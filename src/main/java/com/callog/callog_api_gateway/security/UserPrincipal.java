package com.callog.callog_api_gateway.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.security.Principal;
import java.util.Objects;

//JWT에서 추출한 사용자 정보를 담는 principal 클래스
@Getter
@RequiredArgsConstructor
public class UserPrincipal implements Principal {
    private final String username;
    private final Long userId;

    public UserPrincipal(String username) {
        this.username = username;
        this.userId = null;
    }

    public boolean hasName() {
        return username != null;
    }
    public boolean hasMandatory() {
        return username != null;
    }
    public boolean hasUserId() {
        return userId != null;
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public String getName() {
        return username;
    }

    @Override
    public boolean equals(Object another) {
        if(this == another) return true;
        if(another == null) return false;
        if(!getClass().isAssignableFrom(another.getClass())) return false;

        UserPrincipal principal = (UserPrincipal) another;
        return Objects.equals(username, principal.username) &&
                Objects.equals(userId, principal.userId);
    }

    @Override
    public int hashCode() {
        // HashMap 등에서 사용하기 위한 해시코드 생성
        return Objects.hash(username,userId);
    }
}