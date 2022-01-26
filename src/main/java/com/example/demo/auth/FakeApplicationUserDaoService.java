package com.example.demo.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;
import static com.example.demo.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements  ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {

        List<ApplicationUser> applicationUsers;
        applicationUsers = Lists.newArrayList(
                new ApplicationUser (
                         "ana",
                         passwordEncoder.encode("123"),
                         STUDENT.getGrantedAuthorites(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser (
                        "linda",
                        passwordEncoder.encode("123"),
                        ADMIN.getGrantedAuthorites(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser (
                        "tom",
                        passwordEncoder.encode("123"),
                        ADMIN_TRAINEE.getGrantedAuthorites(),
                        true,
                        true,
                        true,
                        true
                )
        );

        return applicationUsers;
    }
}
