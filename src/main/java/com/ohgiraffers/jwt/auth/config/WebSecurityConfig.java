package com.ohgiraffers.jwt.auth.config;

import com.ohgiraffers.jwt.auth.filter.CustomAuthenticationFilter;
import com.ohgiraffers.jwt.auth.filter.JwtAuthorizationFilter;
import com.ohgiraffers.jwt.auth.handler.CustomAuthFailUserHandler;
import com.ohgiraffers.jwt.auth.handler.CustomAuthSuccessHandler;
import com.ohgiraffers.jwt.auth.handler.CustomAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// https://jwt.io/
@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class WebSecurityConfig {
    /**
     * 1. 정적 자원에 대한 인증된 사용자의 접근을 설정하는 메서드
     * @return WebSeruciryCusomizer
     * */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        // 특정 요청에 대해 spring security filter chain을 건너뛰도록 하는 역할

        // WebConfig에 설정한 addResourceHandler는 정적 자원에 대해 요청을 할 수 있게 해주는 역할
        // WebSecurityCustomizer는 특정 요청에 대해 filterChain을 건너뛰도록 설정하는 역할
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // csrf (Cross Site Request Forgery)
                // RESTAPI 혹은 JWT 기반 인증에서는 session을 사용하지 않아서 보호를 하지 않아도 됨
                .csrf(AbstractHttpConfigurer::disable)
                // 어플리케이션의 session 상태를 비저장 모드로 동작하게 함
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 기존 formLogin을 사용하지 않으므로 비활성화
                .formLogin(AbstractHttpConfigurer::disable)
                // http 기본인증 (JWT를 사용할 것이므로) 비활성화
                .httpBasic(AbstractHttpConfigurer::disable)

                // 사용자가 입력한 id, password를 전달받아 로그인을 직접적으로 수행하는 필터
                // 인증 시(successHandler를 통해) 토큰을 생성해서 header로 전달하고
                // 실패 시(failureHandler를 통해) 실패 이유를 담아서 응답한다.
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)

                // header에 토큰이 담겨져 있을 경우 인가 처리를 해주는 필터
                .addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)

                // 접근 url 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/signup", "/swagger-ui/**", "/v3/api-docs/**", "/swagger-resources/**").permitAll() // Swagger 관련 리소스와 회원가입 경로 허용
//                        .requestMatchers("/api/v1/**").hasRole("ADMIN")
                        .anyRequest()
                        .authenticated()    // 나머지 요청은 인증 필요
                );

        return http.build();
    }

    /**
     * 3. Authentization의 인증 메서드를 제공하는 매니저로 Provider의 인터페이스를 의미한다.
     * @return AuthenticationManager
     * */
    @Bean
    public AuthenticationManager authenticationManager(){
        return new ProviderManager(customAuthenticationProvider());
    }

    /**
     * 4. 사용자의 아이디와 패스워드를 DB와 검증하는 handler이다.
     * @return CustomAuthenticationProvider
     * */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();
    }

    /**
     * 비밀번호를 암호화 하는 인코더
     * @return BCryptPasswordEncoder
     * */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 6. 사용자의 인증 요청을 가로채서 로그인 로직을 수행하는 필터
     * @return CustomAuthenticationFilter
     * */
    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter(){
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager());

        // /login으로 post 요청이 들어오면 필터 동작
        customAuthenticationFilter.setFilterProcessesUrl("/login");

        // 로그인 인증 성공 시 동작할 핸들러 설정 => 토큰 생성
        customAuthenticationFilter.setAuthenticationSuccessHandler(customAuthLoginSuccessHandler());

        // 로그인 인증 실패 시 동작할 핸들러 설정 => exception 처리
        customAuthenticationFilter.setAuthenticationFailureHandler(customAuthFailUserHandler());

        // 필터의 모든 속성 설정을 완료했을 때
        // 올바르게 설정되어 있는지 확인하는 역할의 메소드
        customAuthenticationFilter.afterPropertiesSet();

        // 완성된 CustomAuthenticationFilter 반환
        return customAuthenticationFilter;
    }

    /**
     * 7. spring security 기반의 사용자의 정보가 맞을 경우 결과를 수행하는 handler
     * @return customAuthLoginSuccessHandler
     * */
    @Bean
    public CustomAuthSuccessHandler customAuthLoginSuccessHandler(){
        return new CustomAuthSuccessHandler();
    }

    /**
     * 8. Spring security의 사용자 정보가 맞지 않은 경우 행되는 메서드
     * @return CustomAuthFailUreHandler
     * */
    @Bean
    public CustomAuthFailUserHandler customAuthFailUserHandler(){
        return new CustomAuthFailUserHandler();
    }

    /**
     * 9. 사용자 요청시 수행되는 메소드
     * @return JwtAuthorizationFilter
     * */
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter(){
        return new JwtAuthorizationFilter(authenticationManager());
    }
}
