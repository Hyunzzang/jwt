package com.example.jwt.controller;

import com.example.jwt.dto.JoinRequest;
import com.example.jwt.dto.LoginRequest;
import com.example.jwt.dto.LoginResponse;
import com.example.jwt.dto.TokenInfo;
import com.example.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {
    private final UserService userService;

    @PostMapping("/v1/join")
    public ResponseEntity<Long> join(@RequestBody JoinRequest joinRequest) {
        return ResponseEntity.ok(userService.sigup(joinRequest));
    }

    @PostMapping("/v1/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(new LoginResponse(userService.sigin(loginRequest)));
    }

    @PostMapping("/v2/login")
    public ResponseEntity<TokenInfo> login_v2(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(userService.sigin_v2(loginRequest));
    }
}
