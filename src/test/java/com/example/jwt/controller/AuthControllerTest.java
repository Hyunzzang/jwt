package com.example.jwt.controller;

import com.example.jwt.domain.User;
import com.example.jwt.dto.*;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;


import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

    @Test
    public void renew_정상() throws Exception {
        // 가입
        mvc.perform(post("/api/v1/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new JoinRequest(email, "pw1234"))))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        // 로그인
        MvcResult loginResult = mvc.perform(post("/api/v2/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(email, "pw1234"))))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();

        String logingContent = loginResult.getResponse().getContentAsString();
        TokenInfo logintTokenInfo = objectMapper.readValue(logingContent, TokenInfo.class);

        Thread.sleep(1000L);

        // 토근갱신
        MvcResult renewResult = mvc.perform(post("/api/v2/renew")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RenewRequest(logintTokenInfo.accessToken(), logintTokenInfo.refreshToken()))))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();

        String renewContent = renewResult.getResponse().getContentAsString();
        TokenInfo renewTokenInfo = objectMapper.readValue(renewContent, TokenInfo.class);

        assertThat(renewTokenInfo.accessToken()).isNotEqualTo(logintTokenInfo.accessToken());
        assertThat(renewTokenInfo.refreshToken()).isNotEqualTo(logintTokenInfo.refreshToken());
    }

    @Test
    public void logout_정상() throws Exception {
        // 가입
        mvc.perform(post("/api/v1/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new JoinRequest(email, "pw1234"))))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        // 로그인
        MvcResult loginResult = mvc.perform(post("/api/v2/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(email, "pw1234"))))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();

        String logingContent = loginResult.getResponse().getContentAsString();
        TokenInfo logintTokenInfo = objectMapper.readValue(logingContent, TokenInfo.class);

        // user 정보 검색
        mvc.perform(get("/api/v2/user")
                        .header("Authorization", "Bearer " + logintTokenInfo.accessToken())
                        .contentType(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("email").value(email));


        // 로그아웃
        mvc.perform(post("/api/v2/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LogoutRequest(logintTokenInfo.accessToken(), logintTokenInfo.refreshToken()))))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string("true"));

        // user 정보 검색
        mvc.perform(get("/api/v2/user")
                        .header("Authorization", "Bearer " + logintTokenInfo.accessToken())
                        .contentType(MediaType.APPLICATION_JSON))
                .andDo(print())
                .andExpect(status().isUnauthorized());
    }

}
