package com.ohgiraffers.jwt.auth.filter;

import com.ohgiraffers.jwt.auth.service.CustomUserDetails;
import com.ohgiraffers.jwt.common.AuthConstants;
import com.ohgiraffers.jwt.user.Entity.Member;
import com.ohgiraffers.jwt.user.Entity.Role;
import com.ohgiraffers.jwt.util.TokenUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

/*
* JWT를 사용해 인가처리를 담당하는 필터
*
* HTTP 요청이 들어올 때 JWT 토큰을 확인하고 유효한 토큰의 경우 사용자 정보를
* 인증 컨텍스트에 등록하여 해당 요청이 인증된 사용자로서 처리되도록 한다.
* */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /*
    * url 요청이 왔을 때 인가(권한)가 필요 없는 url
    * 이 필터에 걸리지 않게 처리
    * */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        /*
         * 권한이 필요없는 리소스 추출
         * */
        List<String> roleLeessList = Arrays.asList(
                "/auth/signup",              // 회원가입 시 토큰이 없어도 요청 가능하게
                "/swagger-ui/(.*)",          // swagger 설정
                "/swagger-ui/index.html",    // swagger 설정
                "/v3/api-docs",              // swagger 설정
                "/v3/api-docs/(.*)",         // swagger 설정
                "/swagger-resources",        // swagger 설정
                "/swagger-resources/(.*)"    // swagger 설정
        );
        /*
        * 정규표현식 패턴
        *
        * (.*)
        * - 0개 이상의 임의 문자와 일치하는 패턴
        * - ex) /test/(.*)
        *       "/test/user", "/test/admin"
        *
        * \\d
        * - 숫자 하나와 일치하는 패턴
        * - d+ 하나 이상의 숫자와 일치하는 패턴
        * - ex) /test/\\d+
        *       "/test/1", "/test/123"
        *
        * \\w
        * - 알파벳 문자, 숫자, 언더스코어(_) 하나와 일치하는 패턴
        * - w+ 하나 이상의 알파벳 문자, 숫자, 언더스코어(_)로 이루어진 문자열과 일치하는 패턴
        * - ex) /test/\\w+
        *       "/test/user123"
         * */

        if(roleLeessList.stream().anyMatch(uri -> roleLeessList.stream().anyMatch(pattern -> Pattern.matches(pattern, request.getRequestURI())))){
            chain.doFilter(request,response);
            return;
        }

        // 헤더에서 토큰 꺼내기
        String header = request.getHeader(AuthConstants.AUTH_HEADER);

        // 유효한 토큰인지 확인
        try {
            // 토큰이 비어있는지 확인
            if(header != null && !header.equalsIgnoreCase("")){
                // 토큰 분리 (Bearer 분리시켜서 토큰만 반환)
                String token = TokenUtils.splitHeader(header);

                // 조건식 안에 들어있는 코드를 통해 토큰 검증
                // 검증 결과가 True(유효한 토큰)이면 이후 처리 진행
                if (TokenUtils.isValidToken(token)){
                    // payload에 담긴 (토큰에 담겨있는 정보들)
                    Claims claims = TokenUtils.getClaimsFromToken(token);

                    // 토큰에 담긴 정보로 Member 객체를 만든다.
                    // (SecurityContext에 등록될 인증 객체(UserDetail)을 만들기 위해)
                    Member member = Member.builder()
                            .memberId(claims.get("memberName").toString())
                            .memberEmail(claims.get("memberEmail").toString())
                            .role(Role.valueOf(claims.get("memberRole").toString()))
                            .build();

                    // 토큰에 담겨있던 정보로 인증 객체를 만든다.
                    CustomUserDetails userDetails = new CustomUserDetails();
                    userDetails.setMember(member);

                    // 인증된 사용자 토큰
                    AbstractAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                    // authenticationToken에 추가 정보 설정 (IP, 세션 정보)
                    authenticationToken.setDetails(new WebAuthenticationDetails(request));

                    // SecurityContextHolder에 인증 객체 등록
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    // 다음 필터로 이동
                    chain.doFilter(request, response);
                } else {
                    throw new RuntimeException("토큰이 유효하지 않습니다.");
                }
            } else {
                throw new RuntimeException("토큰이 존재하지 않습니다.");
            }
        } catch (Exception e) {
            // Exception 발생 시 Exception 내용을 응답해준다.
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            PrintWriter printWriter = response.getWriter();

            JSONObject jsonObject = jsonresponseWrapper(e);

            printWriter.print(jsonObject);
            printWriter.flush();
            printWriter.close();
        }
    }

    /**
     * 토큰 관련된 Exception 발생 시 예외 응답
     * */
    private JSONObject jsonresponseWrapper(Exception e) {
        String resultMsg = "";
        if (e instanceof ExpiredJwtException) {
            // 토큰 만료 exception
            resultMsg = "Token Expired";
        } else if (e instanceof SignatureException) {
            resultMsg = "TOKEN SignatureException Login";
        }
        // JWT 토큰내에서 오류 발생 시
        else if (e instanceof JwtException) {
            resultMsg = "TOKEN Parsing JwtException";
        }
        // 이외 JTW 토큰내에서 오류 발생
        else {
            System.out.println(e.getMessage());
            resultMsg = "OTHER TOKEN ERROR";
        }

        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status", 401);
        jsonMap.put("message", resultMsg);
        jsonMap.put("reason", e.getMessage());
        JSONObject jsonObject = new JSONObject(jsonMap);
        return jsonObject;
    }
}
