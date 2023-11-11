package com.serethewind.newauthorizationserver.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import lombok.*;
import org.springframework.boot.autoconfigure.domain.EntityScan;

import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
@Entity
@Table
public class UserEntity extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String firstName;
    @Email
    @Column(unique = true)
    private String email;
    @Column(unique = true)
    private String username;
    private String lastName;
    private String password;
    @Enumerated(EnumType.STRING)
    private Set<RoleEnum> roleEnums = new HashSet<>();
}
