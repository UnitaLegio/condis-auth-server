package com.unitalegio.condis.sso.util;

import java.util.Collection;
import java.util.stream.Collectors;

public interface CollectionMapper<MAIN, SECONDARY> extends Mapper<MAIN, SECONDARY> {
    default Collection<MAIN> mapCollectionFrom(Collection<SECONDARY> modelCollection) {
        return modelCollection.parallelStream().map(this::mapFrom).collect(Collectors.toList());
    }

    default Collection<SECONDARY> mapCollectionTo(Collection<MAIN> mainCollection) {
        return mainCollection.parallelStream().map(this::mapTo).collect(Collectors.toList());
    }
}
