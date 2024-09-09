package com.ohgiraffers.jwt.auth.handler;


import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

/*
* 사용자 로그인 실패시 실패 요청을 커스텀하기 위한 핸들러
* */
public class CustomAuthFailUserHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        JSONObject jsonObject;
        String failMsg;
        if (exception instanceof AuthenticationServiceException) {
            // 사용자의 로그인 또는 인증 처리 과정에서 문제가 발생한다.
            failMsg = "존재하지 않는 사용자입니다.";

        } else if(exception instanceof BadCredentialsException) {
            // BadCredentialsException 오류는 사용자의 아이디가 DB에 존재하지 않는 경우, 비밀번호가 맞지 않는 경우 발생
            failMsg = "아이디 또는 비밀번호가 틀립니다.";

        } else if(exception instanceof LockedException) {
            // 계정이 잠긴 경우 발생
            failMsg ="잠긴 계정입니다.";

        } else if(exception instanceof DisabledException) {
            // 비활성화 된 계정에서 발생
            failMsg ="비활성화된 계정입니다.";

        } else if(exception instanceof AccountExpiredException) {
            // 계정 만료시 발생
            failMsg ="만료된 계정입니다.";

        } else if(exception instanceof CredentialsExpiredException) {
            // 자격 증명이 만료되는 경우 발생
            failMsg = "자격증명이 만료되었습니다.";
        } else if (exception instanceof AuthenticationCredentialsNotFoundException) {
            // 보안 컨텍스트에 인증 객체가 존재하지 않거나 인증 정보가 없는 상태에서 보안처리된 리소스에 접근하는 경우 발생
            failMsg = "인증 요청이 거부되었습니다.";
        }else if (exception instanceof UsernameNotFoundException) {
            // DB에 사용자의 정보가 없는 경우 발생
            failMsg = "존재하지 않는 사용자 입니다.";
        }else{
            failMsg = "정의되있는 케이스의 오류가 아닙니다.";
        }

        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        PrintWriter printWriter = response.getWriter();

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("failType",failMsg);

        jsonObject = new JSONObject(resultMap);

        printWriter.println(jsonObject);
        printWriter.flush();
        printWriter.close();
    }
}
