package com.example.springjwt.domain.user.service;

import com.example.springjwt.domain.user.entity.User;
import com.example.springjwt.domain.user.enums.Role;
import org.springframework.stereotype.Component;

@Component
public class UserServiceImpl implements UserService {
    @Override
    public User getUser(Long id) {
        return new User(id, Role.ROLE_USER);
    }
}
