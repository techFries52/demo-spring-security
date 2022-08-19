package com.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class CustomAuthFilter extends UsernamePasswordAuthenticationFilter {

    // brought in to authenticate the user
    private final AuthenticationManager authenticationManager;

    // constructor injection of authentication manager
    public CustomAuthFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // get credentials from the http request
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        log.info("Username is: {}", username); log.info("Password is: {}", password);

        // creates Token with username and password from request
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // call authentication manager to authenticate the username/password inside the token
        return authenticationManager.authenticate(authenticationToken);

        // can use Object mapper instead of doing it like this too
    }

    // this method gets called when authentication is successful
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
