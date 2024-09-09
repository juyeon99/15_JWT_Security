package com.ohgiraffers.jwt.user.repository;

import com.ohgiraffers.jwt.user.Entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Integer> {

    Optional<Member> findByMemberId(String id);
}
