package com.example.jwt.controller;

import com.example.jwt.dto.JoinRequest;
import com.example.jwt.dto.LoginRequest;
import com.example.jwt.dto.LoginResponse;
import com.example.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    @PostMapping("/join")
    public Long join(@RequestBody JoinRequest joinRequest) {
        return userService.sigup(joinRequest);
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest) {
        return new LoginResponse(userService.sigin(loginRequest));
    }
}
