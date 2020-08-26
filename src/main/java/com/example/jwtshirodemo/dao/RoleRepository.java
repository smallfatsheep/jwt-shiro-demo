package com.example.jwtshirodemo.dao;

import com.example.jwtshirodemo.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role,Long> {
}
