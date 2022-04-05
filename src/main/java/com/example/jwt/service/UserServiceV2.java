package com.example.jwt.service;

import com.example.jwt.domain.User;
import com.example.jwt.dto.LoginRequest;
import com.example.jwt.dto.LogoutRequest;
import com.example.jwt.dto.RenewRequest;
import com.example.jwt.dto.TokenInfo;
import com.example.jwt.repository.TokenRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.security.JwtHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceV2 {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JwtHelper jwtHelper;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public TokenInfo sigin_v2(LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.email())
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(loginRequest.toAuthentication());
        TokenInfo tokenInfo = jwtHelper.generateToken(authentication);
        tokenRepository.saveRefreshToken(authentication.getName(), tokenInfo);

        return tokenInfo;
    }

    public TokenInfo renew(RenewRequest renewRequest) {
        if (!jwtHelper.validateToken(renewRequest.refreshToken())) {
            throw new IllegalArgumentException("Refresh Token이 유효하지 않습니다.");
        }

        Authentication authentication = jwtHelper.getAuthentication(renewRequest.accessToken());
        String storageRefreshToken = tokenRepository.findRefreshToken(authentication.getName());
        if (StringUtils.isEmpty(storageRefreshToken)) {
            throw new IllegalArgumentException("");
        }
        if (!StringUtils.equals(renewRequest.refreshToken(), storageRefreshToken)) {
            throw new IllegalArgumentException("");
        }

        TokenInfo tokenInfo = jwtHelper.generateToken(authentication);
        tokenRepository.saveRefreshToken(authentication.getName(), tokenInfo);

        return tokenInfo;
    }

    public boolean logout_v2(LogoutRequest logoutRequest) {
        if (!jwtHelper.validateToken(logoutRequest.accessToken())) {
            throw new IllegalArgumentException("");
        }
        Authentication authentication = jwtHelper.getAuthentication(logoutRequest.accessToken());
        tokenRepository.deleteRefreshToken(authentication.getName());
        settingLogoutInfo(logoutRequest.accessToken());

        return true;
    }

    private void settingLogoutInfo(String accessToken) {
        tokenRepository.saveLogoutToken(accessToken, jwtHelper.getExpiration(accessToken));
    }
}
