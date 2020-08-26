package com.example.jwtshirodemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletResponse;

@Controller
public class IndexController {

    @RequestMapping("/login1")
    public String loginout(){
        return "login";
    }
    @RequestMapping("/unauthorized")
    public String unauthorized(HttpServletResponse response){
        return "unauthorized";
    }
}
