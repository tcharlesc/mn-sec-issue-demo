package com.example;

import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

@Singleton
public class AuthProviderUserPassword implements AuthenticationProvider {
    private final Logger log = LoggerFactory.getLogger(AuthProviderUserPassword.class);

    public AuthProviderUserPassword() {
    
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> httpRequest,
                                                          AuthenticationRequest<?, ?> req) {
        return Mono.create(emitter -> {

            if (req.getIdentity().equals("test")) {
                emitter.success(AuthenticationResponse.success("testuid"));
            } else {
                log.debug("User:{}, Password:{}, not found", req.getIdentity(), req.getSecret());
                emitter.error(AuthenticationResponse.exception());
            }
        });
    }
}
