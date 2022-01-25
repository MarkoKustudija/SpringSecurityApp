package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

import static com.example.demo.security.ApplicationUserRole.ADMIN;
import static com.example.demo.security.ApplicationUserRole.ADMIN_TRAINEE;

@RestController
@RequestMapping("man/api/v1/students")
public class StudentManagementController {

    private static  final List<Student> STUDENTS = Arrays.asList(
            new Student(1,"Pera Peric"),
            new Student(2, "Mika Mikic"),
            new Student(3, "Ana Anic"),
            new Student(4, "Anica Dobra")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINEE')")
    public  List<Student> getAllStudents(){
        return  STUDENTS;
    }


    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void addNewStudent(@RequestBody Student student){
        System.out.println("Created new student");
        System.out.println(student);
    }


    @PutMapping(path = "/{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable  Integer studentId,@RequestBody Student student){
        System.out.println("Updated student: ");
        System.out.println(String.format("%s %s", student,student));

    }

    @DeleteMapping(path = "/{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable Integer studentId){
        System.out.println("Deleted student : ");
        System.out.println(studentId);
    }


}
