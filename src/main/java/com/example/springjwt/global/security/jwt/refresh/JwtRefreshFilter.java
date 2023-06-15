package com.example.springjwt.global.security.jwt.refresh;

import com.example.springjwt.global.security.jwt.JwtData;
import com.example.springjwt.global.security.jwt.JwtDataService;
import com.example.springjwt.global.security.jwt.data.JwtInvalidException;
import com.example.springjwt.global.security.jwt.JwtManager;
import com.example.springjwt.global.security.jwt.repository.RefreshTokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtRefreshFilter extends OncePerRequestFilter {
    private final String ENDPOINT = "/api/auth/refresh";

    private final String TOKEN_VALUE = "refreshToken";

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final JwtManager jwtManager;
    private final JwtDataService jwtDataService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!request.getServletPath().contains(ENDPOINT) || !request.getMethod().equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }
        ServletInputStream inputStream = request.getInputStream();
        String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
        System.out.println("messageBody = " + messageBody);

        Map<String, Object> jsonBody = objectMapper.readValue(messageBody, Map.class);
        Object refreshTokenObj = jsonBody.get(TOKEN_VALUE);
        if (refreshTokenObj == null || !(refreshTokenObj instanceof String)) {
            filterChain.doFilter(request, response);
            return;
        }
        String refreshToken = (String) refreshTokenObj;
        JwtData jwtData = null;
        try {
            String subject = jwtManager.extractSubject(refreshToken);
            jwtData = jwtDataService.loadBySubject(subject); // 굳이 User 도메인 객체일 필요는 없고, JWT에 들어가야 할 사용자 정보만 포함하고 있으면 됨
        } catch (SignatureException signatureException) {
            throw new JwtInvalidException("서명 키가 다릅니다", signatureException);
        } catch (ExpiredJwtException expiredJwtException) {
            throw new JwtInvalidException("만료된 토큰입니다", expiredJwtException);
        } catch (MalformedJwtException malformedJwtException) {
            throw new JwtInvalidException("잘못된 형식의 토큰입니다", malformedJwtException);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new JwtInvalidException("null과 같은 잘못된 인수를 사용했습니다", illegalArgumentException);
        }
        String newAccessToken = jwtManager.generateAccessToken(jwtData);
        String newRefreshToken = jwtManager.generateRefreshToken(jwtData);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"accessToken\": \"" + newAccessToken + "\", " +
                "\"refreshToken\": \"" + newRefreshToken + "\"}"
        );
        response.getWriter().flush();
    }
}
