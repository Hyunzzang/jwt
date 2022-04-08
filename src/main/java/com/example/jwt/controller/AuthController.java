package com.example.jwt.controller;

import com.example.jwt.dto.*;
import com.example.jwt.service.UserService;
import com.example.jwt.service.UserServiceV2;
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
    private final UserServiceV2 userService_v2;

    @PostMapping("/v1/join")
    public ResponseEntity<Boolean> join(@RequestBody JoinRequest joinRequest) {
        return ResponseEntity.ok(userService.sigup(joinRequest));
    }

    @PostMapping("/v1/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(new LoginResponse(userService.sigin(loginRequest)));
    }

    @PostMapping("/v2/login")
    public ResponseEntity<TokenInfo> login_v2(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(userService_v2.sigin_v2(loginRequest));
    }

    @PostMapping("/v2/renew")
    public ResponseEntity<TokenInfo> renew(@RequestBody RenewRequest renewRequest) {
        return ResponseEntity.ok(userService_v2.renew(renewRequest));
    }

    @PostMapping("/v2/logout")
    public ResponseEntity<Boolean> logout_v2(@RequestBody LogoutRequest logoutRequest) {
        return ResponseEntity.ok(userService_v2.logout_v2(logoutRequest));
    }
}
