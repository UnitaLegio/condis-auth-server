package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.repository.UserEntity;
import com.unitalegio.condis.sso.util.CollectionMapper;

import java.sql.Timestamp;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * Mapper for UserEntity.
 */
class UserEntityMapper implements CollectionMapper<CondisUser, UserEntity> {

    /**
     * Maps from User Entity to User Domain Model.
     *
     * @param entity - entity object;
     * @return user domain model object.
     */
    @Override
    public CondisUser mapFrom(UserEntity entity) {
        return CondisUser.builder()
                .userId(entity.getId())
                .username(entity.getUsername())
                .credentials(entity.getCredentials())
                .email(entity.getEmail())
                .createdAt(entity.getCreatedAt().toLocalDateTime())
                .updatedAt(entity.getUpdatedAt().toLocalDateTime())
                .enabled(entity.getEnabled())
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .build();
    }

    /**
     * Maps from User Domain Model to User Entity.
     *
     * @param model - user domain model object;
     * @return user entity object.
     */
    @Override
    public UserEntity mapTo(CondisUser model) {
        return UserEntity.builder()
                .id(model.getUserId())
                .username(model.getUsername())
                .credentials(model.getCredentials())
                .email(model.getEmail())
                .createdAt(Timestamp.valueOf(model.getCreatedAt()))
                .updatedAt(Timestamp.valueOf(model.getUpdatedAt()))
                .enabled(model.getEnabled())
                .build();
    }
}
