package com.example;

import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.FluxSink;

import java.util.Map;
import java.util.HashMap;

import static io.micronaut.security.errors.IssuingAnAccessTokenErrorCode.INVALID_GRANT;

@Singleton
public class MyRefreshTokenPersistence implements RefreshTokenPersistence {
    private final Logger log = LoggerFactory.getLogger(MyRefreshTokenPersistence.class);
    private final Map<String, String> tokenStore;

    public MyRefreshTokenPersistence() {
        tokenStore = new HashMap<>();
    }

    @Override
    public void persistToken(RefreshTokenGeneratedEvent event) {
        if (event != null &&
                event.getRefreshToken() != null &&
                event.getAuthentication() != null &&
                event.getAuthentication().getName() != null) {
            String payload = event.getRefreshToken();
            String uid = event.getAuthentication().getName();
            log.debug("Save this {} {}", uid, payload);
            tokenStore.put(payload, uid);
        }
    }

    @Override
    public Publisher<Authentication> getAuthentication(String refreshToken) {
        log.debug("Refresh this {}", refreshToken);
        return Flux.create(emitter -> {
            String uid = tokenStore.get(refreshToken);
            if (uid != null) {
                emitter.next(Authentication.build(uid));
                emitter.complete();
            } else {
                emitter.error(new OauthErrorResponseException(INVALID_GRANT, "refresh token not found", null));
            }
        }, FluxSink.OverflowStrategy.ERROR);
    }
}
