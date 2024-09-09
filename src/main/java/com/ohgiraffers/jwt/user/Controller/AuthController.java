package com.ohgiraffers.jwt.user.Controller;

import com.ohgiraffers.jwt.common.ResponseDTO;
import com.ohgiraffers.jwt.user.DTO.MemberDTO;
import com.ohgiraffers.jwt.user.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // 회원가입 요청
    @PostMapping("/signup")
    public ResponseEntity<ResponseDTO> signup(@RequestBody MemberDTO memberDTO) {
        System.out.println(memberDTO);
        MemberDTO savedMemberDTO = authService.signup(memberDTO);

        return ResponseEntity
                .ok()
                .body(new ResponseDTO(HttpStatus.CREATED, "회원가입 성공", savedMemberDTO));
    }
}
