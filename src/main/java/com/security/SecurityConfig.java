package com.security;

import com.filter.CustomAuthenticationFilter;
import com.filter.CustomAuthorizationFilter;
import com.util.TokenWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration @EnableWebSecurity @RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final TokenWriter tokenWriter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // creates custom auth filter to change the default /login for querying to /api/login
        CustomAuthenticationFilter customAuthFilter = new CustomAuthenticationFilter(authenticationManagerBean(), tokenWriter);
        customAuthFilter.setFilterProcessesUrl("/api/login");

        // disable cross site request forgery, springs default session?
        http.csrf().disable();
        // sets session creation policy to stateless
        http.sessionManagement().sessionCreationPolicy(STATELESS);

        // lets everyone access any endpoint on this application
        //http.authorizeRequests().anyRequest().permitAll();

        // lets everyone access this specific url
        http.authorizeRequests().antMatchers( "/api/login/**", "/api/token/refresh/**").permitAll();
        // lets principals with user role access this api route
        http.authorizeRequests().antMatchers(GET, "/api/users/**").hasAnyAuthority("ROLE_USER");
        // lets principals with admin role access this api route
        http.authorizeRequests().antMatchers(POST, "/api/user/save").hasAnyAuthority("ROLE_ADMIN");

        http.authorizeRequests().anyRequest().authenticated();

        // adds our default filter so we can check who is logging in
        // http.addFilter(new CustomAuthFilter(authenticationManagerBean()));

        // or if we have overriden the default path
        http.addFilter(customAuthFilter);
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
