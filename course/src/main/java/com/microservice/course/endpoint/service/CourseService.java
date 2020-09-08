package com.microservice.course.endpoint.service;

import com.microservice.core.model.Course;
import com.microservice.core.repository.CursoRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;


@Service
@Slf4j
@RequiredArgsConstructor(onConstructor= @__(@Autowired))
public class CourseService {
    private final CursoRepository courseRepository;
    public Iterable<Course> courseIterable (Pageable pageable){
        log.info("listing all courses");
        return courseRepository.findAll(pageable);
    }

}
