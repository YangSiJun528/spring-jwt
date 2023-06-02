package com.example.springjwt.domain.user.entity;

import com.example.springjwt.domain.user.enums.Role;
import lombok.Getter;

@Getter
public class User {
    Long id;
    Role role;
}
