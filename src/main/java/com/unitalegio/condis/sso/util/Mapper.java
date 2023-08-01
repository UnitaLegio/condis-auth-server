package com.unitalegio.condis.sso.util;

public interface Mapper<MAIN, AUXILIARY> {

    MAIN mapFrom(AUXILIARY domainModel);

    AUXILIARY mapTo(MAIN MAIN);
}
