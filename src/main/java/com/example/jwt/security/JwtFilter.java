package com.example.jwt.security;

import com.example.jwt.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean {
    private static final String HEADER_KEY_AUTHORIZATION = "Authorization";
    private static final String BEARER_TYPE = "Bearer";

    private final JwtHelper jwtHelper;
    private final TokenRepository tokenRepository;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String token = resolveToken((HttpServletRequest) servletRequest);
        log.info("jwt token: {}", token);
        if (StringUtils.isNotEmpty(token) && jwtHelper.validateToken(token)) {
            if (!tokenRepository.existsLogout(token)) {
                // [주의] Authentication에 authorities 설정 해야함.
                Authentication authentication = jwtHelper.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HEADER_KEY_AUTHORIZATION);
        if (StringUtils.isEmpty(bearerToken)) {
            return null;
        }

        return StringUtils.removeStart(bearerToken, BEARER_TYPE).trim();
    }
}
