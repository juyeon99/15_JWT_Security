package com.ohgiraffers.jwt.user.DTO;

import com.ohgiraffers.jwt.user.Entity.Role;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class MemberDTO {

    private int memberNo;

    private String memberId;

    private String memberPass;

    private String memberName;

    private String memberEmail;

    private Role role;

}
