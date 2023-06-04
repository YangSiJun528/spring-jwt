package com.example.springjwt.global.security.jwt;

import com.example.springjwt.domain.user.entity.User;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class JwtDataImpl implements JwtData {

    User user;

    public JwtDataImpl(User user) {
        this.user = user;
    }

    @Override
    public String getSubject() {
        return String.valueOf(user.getId());
    }

    @Override
    public Set<String> getRoles() {
        return Set.of(String.valueOf(user.getRole()));
    }

    @Override
    public Map<String, Object> getAdditional() {
        String string = "somethingString";
        List<String> list = List.of("somethingList1", "somethingList2", "somethingList3");
        return Map.of("string",string, "list",list);
    }
}
