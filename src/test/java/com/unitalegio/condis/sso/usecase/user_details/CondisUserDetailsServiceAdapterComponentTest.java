package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.repository.UserEntity;
import com.unitalegio.condis.sso.repository.UserRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static com.unitalegio.condis.sso.usecase.user_details.UserDetailsTestUtils.*;

@SpringBootTest
class CondisUserDetailsServiceAdapterComponentTest {
    @Autowired
    private UserRepository repository;
    @Autowired
    private UserDetailsService userDetailsService;

    @Test
    void testUserIsLoadedProperly() {
        // Preparation
        UserEntity testUser =
                createTestEntity(DEFAULT_STARTING_TEST_ID);
        repository.save(testUser);
        UserDetails benchmark = createDefaultUserDetails(DEFAULT_STARTING_TEST_ID);
        // Checking
        UserDetails result = this.userDetailsService
                .loadUserByUsername(TEST_USERNAME + "_" + DEFAULT_STARTING_TEST_ID);
        Assertions.assertNotNull(result);
        Assertions.assertEquals(benchmark, result);
        // Clean up
        repository.delete(testUser);
    }

    @Test
    void testUserNotFoundException() {
        Assertions.assertThrows(
                UsernameNotFoundException.class,
                () -> this.userDetailsService.loadUserByUsername("no user")
        );
    }
}