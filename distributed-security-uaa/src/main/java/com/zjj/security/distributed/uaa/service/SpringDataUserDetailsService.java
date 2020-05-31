package com.zjj.security.distributed.uaa.service;


import com.zjj.security.distributed.uaa.dao.UserDao;
import com.zjj.security.distributed.uaa.model.UserDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author Administrator
 * @version 1.0
 **/
@Service
public class SpringDataUserDetailsService implements UserDetailsService {

    @Autowired
    private UserDao userDao;

    //根据 账号查询用户信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDto user = userDao.getUserByUsername(username);
        if (user==null){
            return null; //provider(DaoAuthenticationProvider)会抛出异常
        }
        List<String> permissionsByUserId = userDao.findPermissionsByUserId(user.getId());
        String[] permissions = new String[permissionsByUserId.size()];
        permissionsByUserId.toArray(permissions);
        UserDetails details = User.withUsername(user.getUsername()).password(user.getPassword()).authorities(permissions).build();

        return details;
    }
}
