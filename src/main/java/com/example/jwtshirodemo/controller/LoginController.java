package com.example.jwtshirodemo.controller;

import com.example.jwtshirodemo.dao.UserRepository;
import com.example.jwtshirodemo.entity.User;
import com.example.jwtshirodemo.jwt.JwtUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: huangwc
 * @Description:
 * @Date: 2020/08/26 14:50:39
 * @Version: 1.0
 */
@Controller
public class LoginController {

    @Autowired
    UserRepository userRepository;

    @RequestMapping("/login")
    public ResponseEntity<Map<String, String>> login(String username, String password) {
        Map<String, String> map = new HashMap<>(2);
        User user = userRepository.getByUsername(username);
        if (user.getUsername().equals(username) && user.getPassword().equals(password)) {
            String token = JwtUtils.sign(username);
            map.put("msg", "登录成功");
            map.put("token", token);
            return ResponseEntity.ok(map);
        }
        map.put("msg", "用户名密码错误");
        return ResponseEntity.ok(map);
    }
    /**
     * 身份认证测试接口
     */
    @RequestMapping("/admin")
    public String admin() {
        return "success";
    }

    /**
     * 角色认证测试接口
     */
    @RequestMapping("/student")
    public String student() {
        return "success";
    }

    /**
     * 权限认证测试接口
     */
    @RequestMapping("/teacher")
    public String teacher() {
        return "success";
    }

}
