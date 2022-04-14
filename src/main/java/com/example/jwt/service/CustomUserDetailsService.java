package com.example.jwt.service;

import com.example.jwt.domain.User;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new IllegalArgumentException("유저 정보가 없습니다."));
    }

    private UserDetails createUserDetails(User users) {
        return new UserPrincipal(users.getId(), users.getEmail(), users.getPassword(),
                Collections.singletonList(users.getRole().getKey()).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    }
}
