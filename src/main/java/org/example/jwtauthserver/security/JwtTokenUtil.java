package org.example.jwtauthserver.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import lombok.extern.java.Log;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@Log
public class JwtTokenUtil {

    @Value("${sicurezza.secret}")
    private String secret;

    private final long expirationTime = 1000 * 60 * 60; // 1 ora

    public String generateToken(String username, String ruolo, String userId) {
        log.info("Generazione del token per l'utente: {}, ruolo: {}, userId: {}" + username +  ruolo + userId);
        Map<String, Object> claims = new HashMap<>();
        claims.put("ruolo", ruolo);
        claims.put("user_id", userId);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS512)
                .compact();
    }


    // Metodo per estrarre il subject (username) dal token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    // Metodo per estrarre la data di scadenza dal token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    // Metodo per controllare se il token è scaduto
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
    //Logica del Token
    // Metodo per verificare se il token può essere aggiornato
    public Boolean canTokenBeRefreshed(String token) {
        return !isTokenExpired(token);
    }

    // Metodo per aggiornare il token
    public String refreshToken(String token) {
        final Claims claims = getAllClaimsFromToken(token);
        return doGenerateToken(claims, getUsernameFromToken(token));
    }

    // Metodo per validare il token
    public Boolean validateToken(String token, String username) {
        final String tokenUsername = getUsernameFromToken(token);
        return (tokenUsername.equals(username) && !isTokenExpired(token));
    }

    // Genera il token effettivo
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes()), SignatureAlgorithm.HS512)
                .compact();
    }

    // Metodo per ottenere specifici claims dal token
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // Metodo per ottenere tutti i claims dal token
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(secret.getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
