package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.util.CollectionMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

import static com.unitalegio.condis.sso.usecase.user_details.UserDetailsTestUtils.*;

class UserDetailsMapperUnitTest {
    private final CollectionMapper<CondisUser, User> mapper = new UserDetailsMapper();
    private final User testUserDetails = createDefaultUserDetails(DEFAULT_STARTING_TEST_ID);
    private final CondisUser testDomainUser = createTestDomainModel(DEFAULT_STARTING_TEST_ID);

    @Test
    void testMapFrom() {
        CondisUser benchmark = testDomainUser.clone();
        cutExcessFields(benchmark);
        CondisUser mappedUser = this.mapper.mapFrom(testUserDetails);
        Assertions.assertNotNull(benchmark);
        Assertions.assertNotNull(mappedUser);
        Assertions.assertNotSame(mappedUser, benchmark);
        Assertions.assertEquals(mappedUser, benchmark);
    }

    private void cutExcessFields(CondisUser benchmark) {
        benchmark.setUserId(null);
        benchmark.setEmail(null);
        benchmark.setCreatedAt(null);
        benchmark.setUpdatedAt(null);
    }

    @Test
    void testMapTo() {
        User mappedEntity = this.mapper.mapTo(testDomainUser);
        Assertions.assertNotNull(testDomainUser);
        Assertions.assertNotNull(mappedEntity);
        Assertions.assertNotSame(mappedEntity, testUserDetails);
        Assertions.assertEquals(mappedEntity, testUserDetails);
    }

    @Test
    void testMapCollectionFrom() {
        int collectionItemsAmount = 5;
        Collection<User> testUserDetailsCollection = createUsersCollection(collectionItemsAmount, User.class);
        Collection<CondisUser> testDomainCollection = createUsersCollection(collectionItemsAmount, CondisUser.class);
        testDomainCollection.forEach(this::cutExcessFields);

        Collection<CondisUser> mappedCollection = this.mapper.mapCollectionFrom(testUserDetailsCollection);

        Assertions.assertFalse(mappedCollection.isEmpty());
        Assertions.assertNotSame(testDomainCollection, mappedCollection);

        org.assertj.core.api.Assertions.assertThat(mappedCollection)
                .containsExactlyInAnyOrderElementsOf(testDomainCollection);
    }

    @Test
    void testMapCollectionTo() {
        int collectionItemsAmount = 5;
        Collection<User> testUserDetailsCollection = createUsersCollection(collectionItemsAmount, User.class);
        Collection<CondisUser> testDomainCollection = createUsersCollection(collectionItemsAmount, CondisUser.class);

        Collection<User> mappedCollection = this.mapper.mapCollectionTo(testDomainCollection);

        Assertions.assertFalse(mappedCollection.isEmpty());
        Assertions.assertNotSame(testUserDetailsCollection, mappedCollection);

        org.assertj.core.api.Assertions.assertThat(mappedCollection)
                .containsExactlyInAnyOrderElementsOf(testUserDetailsCollection);
    }
}