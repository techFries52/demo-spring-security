package com.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.util.TokenWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // brought in to authenticate the user
    private final AuthenticationManager authenticationManager;

    private final TokenWriter tokenWriter;

    // constructor injection of authentication manager
    public CustomAuthenticationFilter(AuthenticationManager authenticationManager, TokenWriter tokenWriter){
        this.authenticationManager = authenticationManager;
        this.tokenWriter = tokenWriter;
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
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authenitcation) throws IOException, ServletException {
        // getting User (Spring security User) from authentication
        User user = (User) authenitcation.getPrincipal();
        // getting Byte algorithm from Java JWT dependency
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

        // creating access token with username, setting expiration, with the request url, with roles
        String access_token = tokenWriter.createAccessToken(request, algorithm, user);
        // creating refresh token with username, setting expiration
        String refresh_token = tokenWriter.createRefreshToken(request,algorithm,user);

        // assigning access token and refresh token to the headers of the response
        // response.setHeader("access_token", access_token);
        // response.setHeader("refresh_token", refresh_token);

        // assign tokens to a Map and assign to the response body
        Map<String,String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }


}
