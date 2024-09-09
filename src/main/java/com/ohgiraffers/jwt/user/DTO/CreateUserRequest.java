package com.ohgiraffers.jwt.user.DTO;

import lombok.*;
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class CreateUserRequest {

    private String userId;
    private String userPass;
    private String userName;
    private String userEmail;

}
