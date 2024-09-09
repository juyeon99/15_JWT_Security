package com.ohgiraffers.jwt.common;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

/* 응답 body에 담길 객체(json문자열이 될 객체) */
@Setter
@Getter
public class ResponseDTO {

    private int status;				// 상태 코드 값
    private String message;			// 응답 메세지
    private Object data;			// 응답 데이터

    public ResponseDTO() {
    }
    public ResponseDTO(HttpStatus status, String message, Object data) {
        super();
        this.status = status.value();		// HttpStatus enum 타입에서 value라는 int형 상태 코드 값만 추출
        this.message = message;
        this.data = data;
    }

    @Override
    public String toString() {
        return "ResponseDTO [status=" + status + ", message=" + message + ", data=" + data + "]";
    }
}