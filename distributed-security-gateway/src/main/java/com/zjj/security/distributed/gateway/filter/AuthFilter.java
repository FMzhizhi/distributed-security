package com.zjj.security.distributed.gateway.filter;

import com.alibaba.fastjson.JSON;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.zjj.security.distributed.gateway.common.EncryptUtil;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AuthFilter extends ZuulFilter {
    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        //越低等级越高
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public boolean shouldFilter() {
        //进行拦截
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        //1获取令牌的内容
        //获取request上下文
        RequestContext ctx = RequestContext.getCurrentContext();
        //从安全上下文中拿 到用户身份对象
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        if (authentication instanceof OAuth2Authentication){
            //无token访问网关内资源的情况，目 前仅有uua服务直接暴露
            return null;
        }
        OAuth2Authentication auth2Authentication= (OAuth2Authentication) authentication;
        Authentication userAuthentication = auth2Authentication.getUserAuthentication();
        //获得身份信息
        Object principal = userAuthentication.getPrincipal();
        //2.组装明文token，转发给微服务，放入header，名称为json‐token
        List<String> authorities=new ArrayList<>();
        //从userAuthentication取出权限，放在authorities
        userAuthentication.getAuthorities().stream().forEach(c->authorities.add(((GrantedAuthority)c).getAuthority()));
        OAuth2Request oAuth2Request = auth2Authentication.getOAuth2Request();

        Map<String, String> requestParameters = oAuth2Request.getRequestParameters();
        Map<String,Object> jsonToken = new HashMap<>(requestParameters);
        if (userAuthentication!=null) {
            jsonToken.put("principal",userAuthentication.getName());
            jsonToken.put("authorities",authorities);
        }
        //把身份信息和权限信息放在json中，加入http的header中,转发给微服务
        ctx.addZuulRequestHeader("json‐token",EncryptUtil.encodeUTF8StringBase64(JSON.toJSONString(jsonToken)));
        return null;
    }
}
