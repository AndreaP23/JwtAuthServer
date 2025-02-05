package org.example.jwtauthserver.controller;

import java.io.Serializable;

import lombok.Data;

@Data
public class JwtTokenRequest implements Serializable
{

    private static final long serialVersionUID = -5616176897013108345L;

    private String email;
    private String password;

}
