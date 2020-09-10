package com.microservice.auth;

import com.microservice.core.model.ApplicationUser;
import com.microservice.core.repository.ApplicationUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class COntrollerTest {
    @Autowired
    ApplicationUserRepository applicationUserRepository;

    @GetMapping("/test")
    public List<ApplicationUser>getTest(){
        return applicationUserRepository.findAll();
    }

    @PostMapping("/test")
    public ApplicationUser getTestPost(@RequestBody ApplicationUser applicationUser){
        ApplicationUser user = applicationUserRepository.findByUsername(applicationUser.getUsername());
        return user;

    }
}
