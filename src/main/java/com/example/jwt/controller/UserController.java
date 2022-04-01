package com.example.jwt.controller;

import com.example.jwt.domain.User;
import com.example.jwt.dto.JoinRequest;
import com.example.jwt.dto.LoginRequest;
import com.example.jwt.dto.LoginResponse;
import com.example.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserController {

    private final UserService userService;

    @GetMapping
    public User getUserInfo(Authentication authentication) {
        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
        Map<String, Object> attributes = token.getTokenAttributes();
        return userService.getUser(attributes.get("email").toString());
    }
}
