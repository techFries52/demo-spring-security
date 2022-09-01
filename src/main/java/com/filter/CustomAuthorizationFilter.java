package com.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")){
            // if user is trying to log in, do nothing and allow user to log in
            log.info("user trying to login: CustomAuthorizationFilter");
            filterChain.doFilter(request,response);
        } else {
            // get authorization header
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            log.info("path was not login or refresh");
            log.info("checking authorization header is not null and starts with Bearer ");
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
                try {
                    log.info("enters try block in CustomAuthorizationFilter");
                    // gets headers
                    String token = authorizationHeader.substring("Bearer ".length());
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                    // uses algorithm to build jwt token, "secret: must be the same as in other class
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    // verifies that jwt is accurate
                    DecodedJWT decodedJWT = verifier.verify(token);
                    // get username and roles from the decoded jwt token
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    // converts a role to a SimpleGrantedAuthority which extends the
                    // Granted Authority that Spring security is looking for
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    // tells spring security: here is the user and their roles and what they can do
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    // lets the request continue on its course
                    // if auth fails at next step it will go to access denied handler
                    filterChain.doFilter(request,response);
                } catch (Exception exception){
                    log.error("Failure to Authorize user, Error logging in: {}", exception.getMessage());

                    // setting Response variables
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(UNAUTHORIZED.value());

                    // creates Map to write to Response Body with new Object Mapper
                    Map<String,String> error = new HashMap<>();
                    error.put("error_message", exception.getMessage());
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                log.info("Authorization Header was null or did not start with 'Bearer '");
                filterChain.doFilter(request,response);
            }
        }
    }
}
