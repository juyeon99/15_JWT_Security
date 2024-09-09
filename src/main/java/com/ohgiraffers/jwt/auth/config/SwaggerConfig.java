package com.ohgiraffers.jwt.auth.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@OpenAPIDefinition(
        info = @Info(title = "JWT 사용 연습",
                description = "JWT 사용 예제",
                version = "v1"))
@Configuration
public class SwaggerConfig {
    @Bean
    public GroupedOpenApi chatOpenApi() {
        String[] paths = {"/api/v1/**", "/auth/**", "/test/**"};    // Swagger에서 처리 되었으면 하는 경로 설정
        return GroupedOpenApi.builder()
                .group("api-v1")
                .pathsToMatch(paths)
                .build();
    }
}
