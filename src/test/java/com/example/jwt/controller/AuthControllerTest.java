package com.example.jwt.controller;

import com.example.jwt.domain.User;
import com.example.jwt.dto.JoinRequest;
import com.example.jwt.dto.LoginRequest;
import com.example.jwt.repository.UserRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;


import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    final String email = "test1201@naver.com";

    @BeforeEach
    public void deleteUser() {
        userRepository.findByEmail(email).ifPresent(user -> userRepository.delete(user));
    }

    @Test
    public void joinTest_정상() throws Exception {
        JoinRequest joinRequest = new JoinRequest(email, "pw1234");

        mvc.perform(post("/api/v1/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(joinRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("true"));
    }

    @Test
    public void joinTest_중복에러() throws Exception {
        JoinRequest joinRequest = new JoinRequest(email, "pw1234");

        mvc.perform(post("/api/v1/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(joinRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        assertThatThrownBy(() -> {
            mvc.perform(post("/api/v1/join")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(joinRequest)))
                    .andDo(print())
                    .andExpect(status().isOk())
                    .andExpect(content().string("true"));
        })
                .hasCauseInstanceOf(IllegalArgumentException.class)
                .hasRootCauseMessage("이미 가입된 이메일 입니다.");
    }

    @Test
    public void login_정상() throws Exception {
        // 가입
        mvc.perform(post("/api/v1/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new JoinRequest(email, "pw1234"))))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        // 로그인
        mvc.perform(post("/api/v2/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(email, "pw1234"))))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("accessToken").isString())
                .andExpect(jsonPath("refreshToken").isString());
    }


}
