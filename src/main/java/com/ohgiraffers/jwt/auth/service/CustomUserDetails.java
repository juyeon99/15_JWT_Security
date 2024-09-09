package com.ohgiraffers.jwt.auth.service;

import com.ohgiraffers.jwt.user.Entity.Member;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
public class CustomUserDetails implements UserDetails { // login 후 SecurityContext에 들어가 있는 정보
    private Member member;

    public String getUserEmail() {
        return member.getMemberEmail();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 회원의 권한을 GrantedAuthority 로 변환
        return Collections.singletonList(new SimpleGrantedAuthority(member.getRole().name()));
    }

    @Override
    public String getPassword() {
        return member.getMemberPass();
    }

    @Override
    public String getUsername() {
        return member.getMemberId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // 계정 만료 여부를 직접 관리하고 싶다면 커스터마이징 가능
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // 계정 잠김 여부
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // 자격 증명 만료 여부
    }

    @Override
    public boolean isEnabled() {
        return true; // 활성화 여부
    }
}
