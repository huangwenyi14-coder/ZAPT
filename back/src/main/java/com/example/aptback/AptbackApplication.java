package com.example.aptback;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("com.example.aptback.mapper")
public class AptbackApplication {

    public static void main(String[] args) {

        SpringApplication.run(AptbackApplication.class, args);
    }

}
