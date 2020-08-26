package com.example.jwtshirodemo.jwt;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * 封装了需要传递的信息
 * 类似UsernamePasswordToken
 */

public class JwtToken implements AuthenticationToken {

    private String jwtoken;

    public JwtToken(String jwtoken) {
        this.jwtoken = jwtoken;
    }

    //获取身份
    @Override
    public Object getPrincipal() {
        return jwtoken;
    }

    //获取凭证
    @Override
    public Object getCredentials() {
        return jwtoken;
    }
}
