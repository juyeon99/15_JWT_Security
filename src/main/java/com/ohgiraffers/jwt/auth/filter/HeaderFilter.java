package com.ohgiraffers.jwt.auth.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.logging.LogRecord;

/*
* CORS 설정을 위한 Filter
*
* CORS (Cross-Origin-Resources-Sharing)
* - 웹 브라우저에서 서로 다른 도메인 간의 자원 공유를 허용하거나 제한하기 위한 보안 메커니즘
*
* 동일 출처 정책: 기본적으로 브라우저는 다른 도메인 간의 리소스 요청을 허용하지 않는다.
* CORS의 역할: 서버가 허용한 특정 도메인에서만 자원을 요청할 수 있도록 설정
*
* CORS 해결 방법
* 1. 서버에서 CORS 설정
*    - 서버가 요청을 허용할 도메인과 메소드, 헤더 등을 명시적으로 작성
* 2. 프록시 서버 사용
*    - 클라이언트와 서버 사잉에 프록시를 사용해 CORS 정책을 우회
* */
public class HeaderFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;
        res.setHeader("Access-Control-Allow-Origin", "*");  // 모든 출처에서의 요청을 허용
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");    // 외부 요청에 허용할 메서드
        res.setHeader("Access-Control-Max-Age", "3600");    // 캐싱을 허용할 시간
        res.setHeader("Access-Control-Allow-Headers",
                "Access-Control-Allow-Origin, Access-Control-Allow-Headers, X-Requested-With, Content-Type, Authorization, X-XSRF-token"
        );  // 허용할 헤더 목록
        res.setHeader("Access-Control-Allow-Credentials", "false"); // 인증정보(쿠키)를 포함한 요청 허용하지 않음
        chain.doFilter(request,response);
    }
}
