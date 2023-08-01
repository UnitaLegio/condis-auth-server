package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.repository.UserEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

class UserDetailsTestUtils {
    static final long DEFAULT_STARTING_TEST_ID = 666;
    static final String TEST_USERNAME = "test_user";
    static final String TEST_CREDENTIAL = "test_credential";
    static final String TEST_EMAIL = "test_email@unitalegio.net";
    static final LocalDateTime TEST_CREATED_DATE = LocalDateTime.now().minusHours(5);
    static final LocalDateTime TEST_UPDATED_DATE = LocalDateTime.now().minusHours(2);

    @SuppressWarnings("unchecked")
    static <T> Collection<T> createUsersCollection(int itemAmount, Class<T> clazz) {
        Collection<T> collection = new ArrayList<>();
        for (int i = 0; i < itemAmount; i++) {
            if (UserEntity.class.equals(clazz)) {
                collection.add((T) createTestEntity(DEFAULT_STARTING_TEST_ID + i));
            } else if (CondisUser.class.equals(clazz)) {
                collection.add((T) createTestDomainModel(DEFAULT_STARTING_TEST_ID + i));
            } else if (UserDetails.class.isAssignableFrom(clazz)) {
                collection.add((T) createDefaultUserDetails(DEFAULT_STARTING_TEST_ID + i));
            }
        }
        return collection;
    }

    static CondisUser createTestDomainModel(long id) {
        return CondisUser.builder()
                .userId(id)
                .username(TEST_USERNAME + "_" + id)
                .credentials(TEST_CREDENTIAL + "_" + id)
                .email(id + "_" + TEST_EMAIL)
                .createdAt(TEST_CREATED_DATE)
                .updatedAt(TEST_UPDATED_DATE)
                .enabled(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .build();
    }

    static UserEntity createTestEntity(long id) {
        return UserEntity.builder()
                .id(id)
                .username(TEST_USERNAME + "_" + id)
                .credentials(TEST_CREDENTIAL + "_" + id)
                .email(id + "_" + TEST_EMAIL)
                .createdAt(Timestamp.valueOf(TEST_CREATED_DATE))
                .updatedAt(Timestamp.valueOf(TEST_UPDATED_DATE))
                .enabled(true)
                .build();
    }

    static User createDefaultUserDetails(long id) {
        return new User(
                TEST_USERNAME + "_" + id,
                TEST_CREDENTIAL + "_" + id,
                true,
                true,
                true,
                true,
                List.of()
        );
    }
}
