package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Base64;
import java.util.Collection;

//import static com.example.demo.security.ApplicationUserRole.ADMIN;
//import static com.example.demo.security.ApplicationUserRole.STUDENT;
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class ApplicationSecurityConfig  extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
                 http
                 .csrf()
                 .disable()
                .authorizeRequests()
                 .antMatchers("/", "index", "/css", "/js/*").permitAll()
                 .antMatchers( "/api/**").hasRole(STUDENT.name())
                 .antMatchers( HttpMethod.POST, "/man/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                 .antMatchers(HttpMethod.GET, "/man/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name())
                 .antMatchers( HttpMethod.PUT, "/man/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers( HttpMethod.DELETE, "/man/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//
//                         .antMatchers( HttpMethod.POST, "/man/api/**").permitAll()
//                         .antMatchers( HttpMethod.PUT, "/man/api/**").hasRole(ADMIN.name())
//                         .antMatchers( HttpMethod.DELETE, "/man/api/**").hasRole(ADMIN.name())
                .anyRequest()
                .authenticated()
                 .and()
                 .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                 .and()
                .httpBasic();

    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
       UserDetails anaUser = User.builder()
                .username("ana")
                .password(passwordEncoder.encode("123"))
//                .roles(STUDENT.name()) // ROLE_STUDENT
               .authorities(STUDENT.getGrantedAuthorites())
                .build();

        UserDetails lindaUser  = User.builder()
             .username("linda")
             .password(passwordEncoder.encode("123"))
//             .roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorites())
             .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("123"))
//                .roles(ADMIN_TRAINEE.name()) // ROLE_ADMIN_TRAINEE
                .authorities(ADMIN_TRAINEE.getGrantedAuthorites())
                .build();

        return  new InMemoryUserDetailsManager(

                anaUser,
                lindaUser,
                tomUser
        );
    }
}
