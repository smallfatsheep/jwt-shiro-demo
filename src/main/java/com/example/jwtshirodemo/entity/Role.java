package com.example.jwtshirodemo.entity;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Setter
@Getter
@Entity
@Table(name = "role")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column
    private String rolename;

    @ManyToMany(mappedBy = "roles")
    private Set<User> users = new HashSet<>();

    @ManyToMany(cascade = CascadeType.ALL,fetch=FetchType.EAGER)
    @JoinTable(
            name = "role_permission",
            joinColumns = {@JoinColumn(name = "role_id",referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "permission_id",referencedColumnName = "id")}
    )
    private Set<Permission> permissions = new HashSet<>();

    public Role(String rolename,Set<Permission> permissions) {
        this.rolename = rolename;
        this.permissions = permissions;
    }

    public Role() {
    }

    public Role(String rolename) {
        this.rolename = rolename;
    }

}
