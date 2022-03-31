package com.example.jwt.controller;

import com.example.jwt.domain.User;
import com.example.jwt.dto.JoinRequest;
import com.example.jwt.dto.LoginRequest;
import com.example.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/join")
    public Long join(@RequestBody JoinRequest joinRequest) {
        return userService.sigup(joinRequest);
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest loginRequest) {
        return userService.sigin(loginRequest);
    }

    @GetMapping("/user")
    public User getUserInfo(@RequestParam String email) {
        return userService.getUser(email);
    }
}
