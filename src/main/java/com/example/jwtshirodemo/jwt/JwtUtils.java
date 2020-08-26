package com.example.jwtshirodemo.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Date;


public class JwtUtils {

    private static final long EXPIRE_TIME = 60 * 1000;

    private static final String SECRET = "huangwc";

    /**
     * @Author: huangwc
     * @Description: 校验token
     * @Date: 2020/8/26 11:24
     * @param token
     * @param username
     * @return: boolean
     **/
    public static boolean verify(String token, String username){
        try{
            //获取加密算法对象(密钥)
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            //获取JWT 验证对象
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("username",username)
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            return true;
        }catch (Exception e){
            return false;
        }
    }

    /**
     * @Author: huangwc
     * @Description: 创建token
     * @Date: 2020/8/26 11:25
     * @param username
     * @return: java.lang.String
     **/
    public static String sign(String username){
        try{
            Date data = new Date(System.currentTimeMillis() + EXPIRE_TIME);
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            return JWT.create()
                    .withClaim("username",username)
                    .withExpiresAt(data)
                    .sign(algorithm);
        }catch (Exception e){
            return null;
        }
    }

    /**
     * @Author: huangwc
     * @Description: 通过token,获取用户名
     * @Date: 2020/8/26 11:25
     * @param token
     * @return: java.lang.String
     **/
    public static String getUsername(String token){
        if (token == null || "".equals(token)){
            return null;
        }
        try{
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        }catch (JWTCreationException e){
            return null;
        }
    }
}
