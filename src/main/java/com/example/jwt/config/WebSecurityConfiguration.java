package com.example.jwt.config;

import com.example.jwt.domain.Role;
import com.example.jwt.security.JwtFilter;
import com.example.jwt.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.example.jwt.security.oauth2.OAuth2AuthenticationFailureHandler;
import com.example.jwt.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.example.jwt.service.CustomOAuth2UserService;
import com.example.jwt.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
@RequiredArgsConstructor
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final JwtFilter jwtFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/h2-console/**");
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        securityConfigure_v2(http);
    }

    /**
     * 단순 JWT 토큰 로그인 설정(v1버전)
     * @param http
     * @throws Exception
     */
    private void securityConfigure_v1(HttpSecurity http) throws Exception {
        http
                .cors()
                .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests(configurer ->
                        configurer
                                .antMatchers(
                                        "/api/v1/join",
                                        "/api/v1/login",
                                        "/h2-console/**"
                                )
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
    }

    /**
     * jwt 기반의 access token, refresh token 토큰 로그인 설정(v2버전)
     *
     * @param http
     * @throws Exception
     */
    private void securityConfigure_v2(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()  // rest api 이므로 기본설정 사용안함.
                .csrf().disable()       // rest api이므로 csrf 보안이 필요없으므로 disable처리.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()    // 다음 리퀘스트에 대한 사용권한 체크
                // 누구나 접근 가능 하도록 아래 uri 등록(가입, 로그인, 로그아웃)
                .antMatchers("/api/v1/join", "/api/v2/login", "/api/v2/renew", "/api/v2/logout", "/h2-console/**").permitAll()
//                .antMatchers("/api/v2/user").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * 소셜 로그인 OAuth2 설정(V3버전)
     * @param http
     * @throws Exception
     */
    private void securityConfigure_v3(HttpSecurity http) throws Exception {
        http.cors()
                .and()
                // 토큰을 사용하기 위해 sessionCreationPolicy를 STATELESS로 설정 (Session 비활성화)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // CSRF 비활성화
                .csrf().disable()
                // 로그인폼 비활성화
                .formLogin().disable()
                // 기본 로그인 창 비활성화
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers("/api/v1/join", "/api/v2/login", "/api/v2/renew", "/api/v2/logout", "/h2-console/**").permitAll()
                .antMatchers("/**").hasAnyRole(Role.GUEST.name() ,Role.USER.name(), Role.ADMIN.name())
                .antMatchers("/auth/**", "/oauth2/**", "/login/oauth2/code/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                // 클라이언트 처음 로그인 시도 URI
                .baseUri("/oauth2/authorization")
                .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                .and()
                .userInfoEndpoint()
                .userService(customOAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler);

        // Add our custom Token based authentication filter
        // UsernamePasswordAuthenticationFilter 앞에 custom 필터 추가!
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
