package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.repository.UserEntity;
import com.unitalegio.condis.sso.util.CollectionMapper;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Collection;

import static com.unitalegio.condis.sso.usecase.user_details.UserDetailsTestUtils.*;

class UserEntityMapperUnitTest {

    private final CollectionMapper<CondisUser, UserEntity> mapper = new UserEntityMapper();
    private final UserEntity testEntity = createTestEntity(DEFAULT_STARTING_TEST_ID);
    private final CondisUser testDomainUser = createTestDomainModel(DEFAULT_STARTING_TEST_ID);

    @Test
    void testMapFrom() {
        CondisUser mappedUser = this.mapper.mapFrom(testEntity);
        Assertions.assertNotNull(testDomainUser);
        Assertions.assertNotNull(mappedUser);
        Assertions.assertNotSame(mappedUser, testDomainUser);
        Assertions.assertEquals(mappedUser, testDomainUser);
    }

    @Test
    void testMapTo() {
        UserEntity mappedEntity = this.mapper.mapTo(testDomainUser);
        Assertions.assertNotNull(testDomainUser);
        Assertions.assertNotNull(mappedEntity);
        Assertions.assertNotSame(mappedEntity, testEntity);
        Assertions.assertEquals(mappedEntity, testEntity);
    }

    @Test
    void testMapCollectionFrom() {
        int collectionItemsAmount = 5;
        Collection<UserEntity> testEntityCollection = createUsersCollection(collectionItemsAmount, UserEntity.class);
        Collection<CondisUser> testDomainCollection = createUsersCollection(collectionItemsAmount, CondisUser.class);

        Collection<CondisUser> mappedCollection = this.mapper.mapCollectionFrom(testEntityCollection);

        Assertions.assertFalse(mappedCollection.isEmpty());
        Assertions.assertNotSame(testDomainCollection, mappedCollection);

        org.assertj.core.api.Assertions.assertThat(mappedCollection)
                .containsExactlyInAnyOrderElementsOf(testDomainCollection);
    }

    @Test
    void testMapCollectionTo() {
        int collectionItemsAmount = 5;
        Collection<UserEntity> testEntityCollection = createUsersCollection(collectionItemsAmount, UserEntity.class);
        Collection<CondisUser> testDomainCollection = createUsersCollection(collectionItemsAmount, CondisUser.class);

        Collection<UserEntity> mappedCollection = this.mapper.mapCollectionTo(testDomainCollection);

        Assertions.assertFalse(mappedCollection.isEmpty());
        Assertions.assertNotSame(testEntityCollection, mappedCollection);

        org.assertj.core.api.Assertions.assertThat(mappedCollection)
                .containsExactlyInAnyOrderElementsOf(testEntityCollection);
    }

}