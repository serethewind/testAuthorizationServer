package com.serethewind.newauthorizationserver.repository;
import com.serethewind.newauthorizationserver.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {



    @Query("select u from UserEntity u where u.username = ?1 or u.email = ?2")
    Optional<UserEntity> findByUsernameOrEmail(String username, String email);
}
