package com.example.jwtshirodemo.shiro;


import com.example.jwtshirodemo.dao.UserRepository;
import com.example.jwtshirodemo.entity.Role;
import com.example.jwtshirodemo.entity.User;
import com.example.jwtshirodemo.jwt.JwtToken;
import com.example.jwtshirodemo.jwt.JwtUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;

/**
 * doGetAuthenticationInfo() 方法：用来验证当前登录的用户，获取认证信息。
 * doGetAuthorizationInfo() 方法：为当前登录成功的用户授予权限和分配角色。
 */
public class MyRealm extends AuthorizingRealm {

    @Autowired
    private UserRepository userRepository;

    /**
     * 多重写一个support
     * 标识这个Realm是专门用来验证JwtToken
     * 不负责验证其他的token（UsernamePasswordToken）
     * */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    /**
     * @Author: huangwc
     * @Description: 授权
     * @Date: 2020/8/26 14:09
     * @param principalCollection
     * @return: org.apache.shiro.authz.AuthorizationInfo
     **/
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        // 获取token
        String token = principalCollection.getPrimaryPrincipal().toString();
        System.out.println("token:" + token);
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        // 给该用户设置角色，角色信息存在 t_role 表中取
        String username = JwtUtils.getUsername(token);
        User user = userRepository.getByUsername(username);
        Set<String> roles = new HashSet<>();
        for (Role role : user.getRoles()){
            roles.add(role.getRolename());
        }
        authorizationInfo.setRoles(roles);
        // 给该用户设置权限，权限信息存在 t_permission 表中取
        authorizationInfo.setStringPermissions(userRepository.getPermissions(roles));
        return authorizationInfo;
    }

    /**
     * @Author: huangwc
     * @Description: 认证
     * @Date: 2020/8/26 14:09
     * @param authenticationToken
     * @return: org.apache.shiro.authc.AuthenticationInfo
     **/
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 根据 Token 获取用户名，如果您不知道该 Token 怎么来的，先可以不管，下文会解释
        String token = authenticationToken.getPrincipal().toString();
        System.out.println("token:" + token);
        if (token == null) {
            throw new NullPointerException("token 不允许为空");
        }
        String username = JwtUtils.getUsername(token);
        //判断
        if (!JwtUtils.verify(token,username)) {
            throw new UnknownAccountException();
        }
        // 根据用户名从数据库中查询该用户,判断是否真实存在
        User user = userRepository.getByUsername(username);
        if(user != null) {
            // 传入用户名和密码进行身份认证，并返回认证信息
            // 这里返回的是账号密码，但是JwtToken都是jwt字符串。还需要一个该Realm(MyRealm)的类名
            AuthenticationInfo authcInfo = new SimpleAuthenticationInfo(token, token, getName());
            return authcInfo;
        } else {
            return null;
        }
    }
}
