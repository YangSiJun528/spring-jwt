package com.example.springjwt.global.security.domain.user.entity;

import com.example.springjwt.global.security.domain.user.enums.Role;
import lombok.Getter;

@Getter
public class User {
    Long id;
    Role role;
}
