package org.example.jwtauthserver.security;

import io.jsonwebtoken.Clock;
import java.util.Date;

public class SystemClock implements Clock {
    @Override
    public Date now() {
        return new Date();
    }
}
