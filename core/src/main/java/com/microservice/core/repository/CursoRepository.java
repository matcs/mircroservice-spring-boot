package com.microservice.core.repository;

import com.microservice.core.model.Course;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface CursoRepository extends PagingAndSortingRepository<Course,Long> {
}
