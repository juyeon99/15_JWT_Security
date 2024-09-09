package com.ohgiraffers.jwt.auth.handler;

import com.ohgiraffers.jwt.auth.service.CustomUserDetails;
import com.ohgiraffers.jwt.common.AuthConstants;
import com.ohgiraffers.jwt.user.Entity.Member;
import com.ohgiraffers.jwt.util.ConvertUtil;
import com.ohgiraffers.jwt.util.TokenUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

/*
* 로그인 성공했을 때 동작하는 핸들러
* JWT를 생성하고 responseHeader(응답 헤더)를 넘겨주는 역할
* */
@Configuration
public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        // Security Context에 저장된 로그인한 사용자 정보를 꺼내온다.
        Member member = ((CustomUserDetails) authentication.getPrincipal()).getMember();

        // Member 객체를 JSON 형태의 객체로 변환
        JSONObject jsonValue = (JSONObject) ConvertUtil.convertObjectToJsonObject(member);

        // 응답하기 위한 Map
        HashMap<String, Object> responseMap = new HashMap<>();

        // 응답하기 위해 담아주는 역할
        responseMap.put("userInfo", jsonValue);
        responseMap.put("message", "로그인 성공");

        // 토큰 생성
        String token = TokenUtils.generateJwtToken(member);

        // 헤더에 토큰 담기
        response.addHeader(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + token);

        // responseMap을 JSONObject로 변환
        JSONObject jsonObject = new JSONObject(responseMap);
        response.setCharacterEncoding("UTF-8");         // 응답 인코딩 설정
        response.setContentType("application/json");    // 응답 MIME 설정

        // 만든 response를 내보내기
        PrintWriter printWriter = response.getWriter();
        printWriter.println(jsonObject);
        printWriter.flush();
        printWriter.close();
    }
}
