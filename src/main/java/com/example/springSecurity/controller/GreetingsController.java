package com.example.springSecurity.controller;

import com.example.springSecurity.jwt.JwtUtils;
import com.example.springSecurity.model.LoginRequest;
import com.example.springSecurity.model.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {


    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;



    @GetMapping("/hello")
    public String sayHello(){
        return "Hello";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/hello")
    public String userEndPoint(){
        return "Hello, user";
    }

    @PreAuthorize("hasRole('ADMIN')")

    @GetMapping("/admin/hello")
    public String userAdminPoint(){
        return "Hello, Admin";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;
       try{
           authentication=authenticationManager.authenticate(
                   new UsernamePasswordAuthenticationToken(loginRequest.getUserName(),loginRequest.getPassword()));

       }
       catch(AuthenticationException e){

           Map<String, Object> map = new HashMap<>();
           map.put("message","Bad Credentials");
           map.put("status",false);
           return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
       }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken =jwtUtils.generateTokenFromUser(userDetails);

        List<String> roles=userDetails.getAuthorities().stream().
                map(GrantedAuthority::getAuthority).toList();

        LoginResponse loginResponse = new LoginResponse(jwtToken,userDetails.getUsername(),roles);
        return ResponseEntity.ok(loginResponse);
    }
}
