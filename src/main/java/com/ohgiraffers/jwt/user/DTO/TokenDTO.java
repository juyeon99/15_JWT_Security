package com.ohgiraffers.jwt.user.DTO;

import lombok.*;

/* 토큰 정보 담을 객체*/
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
@ToString
@Builder
public class TokenDTO {

    private String grantType;       // 토큰 타입
    private String memberName;      // 인증받은 회원 이름
    private String accessToken;     // 엑세스 토큰

}
