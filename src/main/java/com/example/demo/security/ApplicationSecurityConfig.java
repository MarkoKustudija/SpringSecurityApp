package com.example.demo.security;

import com.example.demo.auth.ApplicationUser;
import com.example.demo.auth.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

//import static com.example.demo.security.ApplicationUserRole.ADMIN;
//import static com.example.demo.security.ApplicationUserRole.STUDENT;
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class ApplicationSecurityConfig  extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private  final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
             http
                .csrf().disable()
                     //                 .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
                     .authorizeRequests()
                     .antMatchers("/", "index", "login", "courses",  "/css/*", "/js/*").permitAll()
                     .antMatchers("/api/**").hasRole(STUDENT.name())
                     .anyRequest()
                     .authenticated()
                     .and()
                     .formLogin();
//                     .loginPage("/login")
//                     .permitAll()
//                     .defaultSuccessUrl("/courses", true)
//                     .passwordParameter("password")
//                     .usernameParameter("username")
//                     .and()
//                     .rememberMe()
//                     .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                     .key("somethingverysecured")
//                     .rememberMeParameter("remember-me")
//                     .and()
//                     .logout()
//                     .logoutUrl("/logout")
//                     .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // https://docs.spring.io/spring-security/site/docs/4.2.12.RELEASE/apidocs/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html
//                     .clearAuthentication(true)
//                     .invalidateHttpSession(true)
//                     .deleteCookies("JSESSIONID", "remember-me")
//                      .logoutSuccessUrl("/login");
    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//       UserDetails anaUser = User.builder()
//                .username("ana")
//                .password(passwordEncoder.encode("123"))
////                .roles(STUDENT.name()) // ROLE_STUDENT
//               .authorities(STUDENT.getGrantedAuthorites())
//                .build();
//
//        UserDetails lindaUser  = User.builder()
//             .username("linda")
//             .password(passwordEncoder.encode("123"))
////             .roles(ADMIN.name()) //ROLE_ADMIN
//                .authorities(ADMIN.getGrantedAuthorites())
//             .build();
//
//        UserDetails tomUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("123"))
////                .roles(ADMIN_TRAINEE.name()) // ROLE_ADMIN_TRAINEE
//                .authorities(ADMIN_TRAINEE.getGrantedAuthorites())
//                .build();
//
//        return  new InMemoryUserDetailsManager(
//
//                anaUser,
//                lindaUser,
//                tomUser
//        );
//    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);


        return  provider;

    }

}
