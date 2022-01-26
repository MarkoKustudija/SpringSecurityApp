package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/")
public class TemplateController {

    @GetMapping("/login.html")
    public String getLogin() {
        return "login";
    }

    @GetMapping("/courses")
    public String getCourses() {
        return "courses";
    }
}
