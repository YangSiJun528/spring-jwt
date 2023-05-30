package com.example.springjwt.global.security.jwt;

import java.util.Objects;

// TODO 이름 바꾸기
public final class TokenVO {
    private final String accessToken;
    private final String refreshToken;

    public TokenVO(
            String accessToken,
            String refreshToken
    ) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (TokenVO) obj;
        return Objects.equals(this.accessToken, that.accessToken) &&
                Objects.equals(this.refreshToken, that.refreshToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accessToken, refreshToken);
    }

    @Override
    public String toString() {
        return "TokenVO[" +
                "accessToken=" + accessToken + ", " +
                "refreshToken=" + refreshToken + ']';
    }

}
