package com.example.jwt.security.oauth2;

import com.example.jwt.domain.AuthProvider;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else {
            throw new UnsupportedOperationException(registrationId + " 로그인은 지원하지 않습니다.");
        }
    }
}
