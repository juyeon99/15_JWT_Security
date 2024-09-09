package com.ohgiraffers.jwt.auth.filter;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ohgiraffers.jwt.user.DTO.MemberDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

/*
* 로그인 URL로 POST 요청이 오면 요청을 가로채서 아이디와 비밀번호 추출
*
* 작동방식
* 1. 로그인 URL로 오는 요청을 가로챈다.
* 2. 로그인 정보 추출
* 3. 인증처리 AuthenticationManager를 통해 실제 인증 처리
* 4. 인증에 성공하면 인증 정보를 저장한 Authentication 반환
* */
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 로그인 정보를 추출해서 AuthenticationManager를 통해 로그인 정보를 넘겨준다.
        UsernamePasswordAuthenticationToken authRequest;

        try {
            authRequest = getAuthRequest(request);
            setDetails(request, authRequest);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * 사용자의 로그인 리소스 요청시 요청 정보를 임시 토큰에 저장하는 메서드
     *
     * @param request - httpServletRequest
     * @return UserPasswordAuthenticationToken
     * @throw Excpetion e
     * */
    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        objectMapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE,true);
        MemberDTO member = objectMapper.readValue(request.getInputStream(), MemberDTO.class);

        return new UsernamePasswordAuthenticationToken(member.getMemberId(), member.getMemberPass());
    }
}
