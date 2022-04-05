package com.example.jwt.service;

import com.example.jwt.domain.User;
import com.example.jwt.dto.JoinRequest;
import com.example.jwt.dto.LoginRequest;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.security.JwtHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final JwtHelper jwtHelper;
    private final BCryptPasswordEncoder passwordEncoder;

    public long sigup(JoinRequest joinRequest) {
        if (userRepository.existsByEmail(joinRequest.email())) {
            throw new IllegalArgumentException("이미 가입된 이메일 입니다.");
        }

        return userRepository.save(User.builder()
                .email(joinRequest.email())
                .password(passwordEncoder.encode(joinRequest.password()))
                .build()).getId();
    }

    public String sigin(LoginRequest loginRequest) {
        User user = userRepository.findByEmail(loginRequest.email())
                .orElseThrow(() -> new IllegalArgumentException("유저 정보가 없습니다."));

        if (!passwordEncoder.matches(loginRequest.password(), user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        Map<String, String> claims = new HashMap<>();
        claims.put("email", user.getEmail());

        return jwtHelper.createJwtForClaims(user.getEmail(), claims);
    }

    public User getUser(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));
    }
}
