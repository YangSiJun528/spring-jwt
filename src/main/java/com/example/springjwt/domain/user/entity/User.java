package com.example.springjwt.domain.user.entity;

import com.example.springjwt.domain.user.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.stereotype.Component;

@Getter
@AllArgsConstructor
public class User {
    Long id;
    Role role;
}
