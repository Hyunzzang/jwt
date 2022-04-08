package com.example.jwt.controller;

import com.example.jwt.domain.User;
import com.example.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    // todo: 운영환경에서는 도메인객체(Entity)를 response로 안내려 주도록 하자.
    @GetMapping("/v1/user")
    public ResponseEntity<User> getUserInfo(Authentication authentication) {
        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
        Map<String, Object> attributes = token.getTokenAttributes();
        return ResponseEntity.ok(userService.getUser(attributes.get("email").toString()));
    }

    @GetMapping("/v2/user")
    public ResponseEntity<User> getUserInfo_v2() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // todo: authentication 없을 경우의 에러 처리

        return ResponseEntity.ok(userService.getUser(authentication.getName()));
    }
}
