package com.microservice.auth.security.user;

import com.microservice.core.model.ApplicationUser;
import com.microservice.core.repository.ApplicationUserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.concurrent.CompletableFuture;

@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    ApplicationUserRepository applicationUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Searching in the DB");

        //using this directly will not work
        ApplicationUser applicationUser = applicationUserRepository.findByUsername(username);

        System.out.println(applicationUser);

        //to return the ApplicationUser correctly, you need these functions
        ApplicationUser user = new ApplicationUser(0L,"generic","password","none");
        user.setId(applicationUser.getId());
        user.setUsername(applicationUser.getUsername());
        user.setPassword(new BCryptPasswordEncoder().encode(applicationUser.getPassword()));
        user.setRole(applicationUser.getRole());

        if(applicationUser==null)
            throw new UsernameNotFoundException("User Not Found");

        return new CustomUserDetails(user);
    }

    private static final class CustomUserDetails extends ApplicationUser implements UserDetails{
        public CustomUserDetails(ApplicationUser applicationUser) {
            super(applicationUser);
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_"+this.getRole());
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
