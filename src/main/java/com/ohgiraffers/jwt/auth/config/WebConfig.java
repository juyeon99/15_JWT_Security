package com.ohgiraffers.jwt.auth.config;

import com.ohgiraffers.jwt.auth.filter.HeaderFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
// 정적 자원에 대해 url 요청을 할 수 있게 해주는 것
public class WebConfig implements WebMvcConfigurer {
    // 정적 자원에 접근을 허용하게 하기 위함
    private static final String[] CLASSPATH_RESOURCE_LOCATIONS = {"classpath:/static/", "classpath:/public/",
            "classpath:/", "classpath:/resources/", "classpath:/META-INF/resources/",
            "classpath:/META-INF/resources/webjars/"};

    // ResourceHandlerRegistry 객체를 사용해 하나이상의 리소스 핸들러를 등록 가능
    // addResourceHandler: 특정 URL 패턴에 대한 요청을 처리할 리소스 핸들러 등록
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // 모든 url 패턴에대해 정적 자원에 접근이 가능하도록 한다.
        registry.addResourceHandler("/**").addResourceLocations(CLASSPATH_RESOURCE_LOCATIONS);
    }

    @Bean
    public HeaderFilter createHeaderFilter() {
        return new HeaderFilter();
    }
}
