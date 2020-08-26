package com.example.jwtshirodemo.jwt;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;


/**
 * 自定义一个Filter，用来拦截所有的请求判断是否携带Token
 * */
public class JwtFilter extends BasicHttpAuthenticationFilter {

    /**
     * 这里我们详细说明下为什么最终返回的都是true，即允许访问
     * 例如我们提供一个地址 GET /article
     * 登入用户和游客看到的内容是不同的
     * 如果在这里返回了false，请求会被直接拦截，用户看不到任何东西
     * 所以我们在这里返回true，Controller中可以通过 subject.isAuthenticated() 来判断用户是否登入
     * 如果有些资源只有登入用户才能访问，我们只需要在方法上面加上 @RequiresAuthentication 注解即可
     * 但是这样做有一个缺点，就是不能够对GET,POST等请求进行分别过滤鉴权(因为我们重写了官方的方法)，但实际上对应用影响不大
     */
    /**
     * @Author: huangwc
     * @Description: isAccessAllowed()判断是否携带了有效的JwtToken
     * @Date: 2020/8/26 13:39
     * @param request
     * @param response
     * @param mappedValue
     * @return: boolean
     **/
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginAttempt(request, response)) {
            try {
                return executeLogin(request, response);
            } catch (Exception e) {
                throw new AuthorizationException("权限不足", e);
            }
        }
        return true;
    }

    /**
     * 判断用户是否想要登入。
     * 检测header里面是否包含Authorization字段即可
     * @param request
     * @param response
     * @return
     */
    @Override
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        HttpServletRequest req = (HttpServletRequest) request;
        //判断是否是登录请求
        //这个地方和前端约定，要求前端将jwtToken放在请求的Header部分
        //所以以后发起请求的时候就需要在Header中放一个Authorization，值就是对应的Token
        String authorization = req.getHeader("token");
        return authorization != null;
    }

    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest req = (HttpServletRequest) request;
        Map<String, String> map = new HashMap<>(2);
        String header = req.getHeader("token");
        JwtToken token = new JwtToken(header);
        // 提交给realm进行登入，如果错误他会抛出异常并被捕获
        try {
        getSubject(request, response).login(token);
        // 如果没有抛出异常则代表登入成功，返回true
        } catch (Exception e) {
            e.printStackTrace();
            //调用下面的方法向客户端返回错误信息
            return false;
        }
        return true;
    }

    /**
     * @Author: huangwc
     * @Description: onAccessDenied()是没有携带JwtToken的时候进行账号密码登录，登录成功允许访问，登录失败拒绝访问
     * @Date: 2020/8/26 13:40
     * @param servletRequest
     * @param servletResponse
     * @return: boolean
     **/
    /*@Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String jwt = request.getHeader("Authorization");
        JwtToken jwtToken = new JwtToken(jwt);
        *//*
         * 下面就是固定写法
         * *//*
        try {
            // 委托 realm 进行登录认证
            //所以这个地方最终还是调用JwtRealm进行的认证
            getSubject(servletRequest, servletResponse).login(jwtToken);
            //也就是subject.login(token)
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        //执行方法中没有抛出异常就表示登录成功
        return true;
    }*/

    /**
     * 对跨域提供支持
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            httpServletResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(request, response);
    }
}
