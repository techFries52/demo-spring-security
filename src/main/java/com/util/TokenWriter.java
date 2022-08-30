package com.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.models.AppUser;
import com.models.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.stream.Collectors;
@Component
public class TokenWriter {


    public String createAccessToken(HttpServletRequest request,Algorithm algorithm, User user) {
        // creating access token with username, setting expiration, with the request url, with roles
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

    }

    public String createAccessTokenWithAppUser (HttpServletRequest request, Algorithm algorithm, AppUser user){
         return JWT.create()
                 .withSubject(user.getUsername())
                 .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                 .withIssuer(request.getRequestURL().toString())
                 .withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
                 .sign(algorithm);
    }

    public String createRefreshToken(HttpServletRequest request, Algorithm algorithm, User user){
        // creating refresh token with username, setting expiration
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
    }
}
