package com.ohgiraffers.jwt.user.Entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Table(name="TBL_USER")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Builder
@ToString
public class Member {

    @Id
    @Column(name = "MEMBER_NO")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int memberNo;

    @Column(name = "MEMBER_ID")
    private String memberId;

    @Column(name = "MEMBER_PASS")
    private String memberPass;

    @Column(name = "MEMBER_NAME")
    private String memberName;

    @Column(name = "MEMBER_EMAIL")
    private String memberEmail;

    @Enumerated(value = EnumType.STRING)
    @Column(name = "MEMBER_ROLE")
    private Role role;

}
