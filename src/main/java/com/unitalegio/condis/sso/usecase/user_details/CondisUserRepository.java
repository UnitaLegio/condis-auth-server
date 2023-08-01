package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.repository.UserEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CondisUserRepository extends CrudRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername(String userName);

    Optional<UserEntity> findByEmail(String email);
}
