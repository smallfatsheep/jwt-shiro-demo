package com.example.jwtshirodemo.dao;

import com.example.jwtshirodemo.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionRepository extends JpaRepository<Permission,Long> {
}
