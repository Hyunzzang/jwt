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
     * ?????? JWT ?????? ????????? ??????(v1??????)
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
     * jwt ????????? access token, refresh token ?????? ????????? ??????(v2??????)
     *
     * @param http
     * @throws Exception
     */
    private void securityConfigure_v2(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()  // rest api ????????? ???????????? ????????????.
                .csrf().disable()       // rest api????????? csrf ????????? ?????????????????? disable??????.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()    // ?????? ??????????????? ?????? ???????????? ??????
                // ????????? ?????? ?????? ????????? ?????? uri ??????(??????, ?????????, ????????????)
                .antMatchers("/api/v1/join", "/api/v2/login", "/api/v2/renew", "/api/v2/logout", "/h2-console/**").permitAll()
//                .antMatchers("/api/v2/user").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * ?????? ????????? OAuth2 ??????(V3??????)
     * @param http
     * @throws Exception
     */
    private void securityConfigure_v3(HttpSecurity http) throws Exception {
        http.cors()
                .and()
                // ????????? ???????????? ?????? sessionCreationPolicy??? STATELESS??? ?????? (Session ????????????)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // CSRF ????????????
                .csrf().disable()
                // ???????????? ????????????
                .formLogin().disable()
                // ?????? ????????? ??? ????????????
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers("/api/v1/join", "/api/v2/login", "/api/v2/renew", "/api/v2/logout", "/h2-console/**").permitAll()
                .antMatchers("/**").hasAnyRole(Role.GUEST.name() ,Role.USER.name(), Role.ADMIN.name())
                .antMatchers("/auth/**", "/oauth2/**", "/login/oauth2/code/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                // ??????????????? ?????? ????????? ?????? URI
                .baseUri("/oauth2/authorization")
                .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                .and()
                .userInfoEndpoint()
                .userService(customOAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler);

        // Add our custom Token based authentication filter
        // UsernamePasswordAuthenticationFilter ?????? custom ?????? ??????!
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
