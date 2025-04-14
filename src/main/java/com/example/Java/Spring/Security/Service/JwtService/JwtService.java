package com.example.Java.Spring.Security.Service.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

@Service
public class JwtService {

//    @Value("${secret.key}")
//    private String secretKey;
    private final String SECRET_KEY = "q1X2z7vb9D4l8G1e3R6j0N5p2S9v6Y3f1C8i4U7o2J1m5Z9x3L0g4R8m7K2q3B6";

    /**
     * to get signing key (will decode the SECRET_KEY into byte Array)
     * Keys.hmacShaKeyFor(decodeByteKey) is a method in the JJWT library (for Java JWTs).
     * It takes a byte array (decodeByteKey) representing a secret key and creates a SecretKey object
     * suitable for HMAC-SHA algorithms (like HS256, HS384, HS512) used to sign and verify JWTs.
     * This ensures a properly formatted key for secure JWT operations.
     */
    private Key getSigningKey() {
        byte[] decodeByteKey = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(decodeByteKey);
    }

    /**
     * This Java method populateAuthorities takes a collection of GrantedAuthority objects (typically
     * representing user roles or permissions in Spring Security). It iterates through this collection,
     * extracts the authority string from each GrantedAuthority, and adds it to a HashSet to ensure
     * uniqueness. Finally, it joins these unique authority strings into a single comma-separated string
     * (e.g., "USER,HR,MANAGER") and returns it. This string is often used to store or transmit user
     * authorities in a compact format, such as within a JWT claim.
     */
    private String populateAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<String> authoritiesSet = new HashSet<>();
        for (GrantedAuthority authority : authorities) {
            authoritiesSet.add(authority.getAuthority());
        }
        //USER, HR, MANAGER
        return String.join(",", authoritiesSet);
    }

    /**
     * This Java method generateToken takes a UserDetails object (from Spring Security, containing user information) and creates a JWT (JSON Web Token).
     * <p>
     * 1. It starts building the JWT using Jwts.builder().<p>
     * 2. setSubject(user.getUsername()) sets the "subject" claim of the JWT to the user's username.<p>
     * 3. claim("authorities", populateAuthorities(user.getAuthorities())) adds a custom claim named "authorities" containing a comma-separated string of the user's roles/permissions, obtained by calling the populateAuthorities method.<p>
     * 4. setIssuedAt(new Date(System.currentTimeMillis())) sets the "issued at" claim to the current timestamp.<p>
     * 5. setExpiration(new Date(System.currentTimeMillis() + 86400000)) sets the "expiration time" claim to 24 hours (86,400,000 milliseconds) in the future.<p>
     * 6. signWith(getSigningKey(), SignatureAlgorithm.HS256) signs the JWT using the HS256 algorithm and a secret key obtained from the getSigningKey() method, ensuring the token's integrity.<p>
     * 7. .compact() builds and serializes the JWT into a compact string format.<p>
     */
    //generate Token
    public String generateToken(UserDetails user) {
        return Jwts.builder()
                .setSubject(user.getUsername())
                .claim("authorities", populateAuthorities(user.getAuthorities()))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    /**
     * This Java method extractAllClaims takes a JWT string (token) and extracts all the claims (key-value pairs) it contains.
     * <p>
     * 1. Jwts.parserBuilder() starts building a JWT parser.<p>
     * 2. .setSigningKey(getSigningKey()) sets the secret key used to verify the JWT's signature. This ensures that only tokens signed with the correct key can be parsed successfully.<p>
     * 3. .build() creates the JWT parser.<p>
     * 4. .parseClaimsJwt(token) parses the provided JWT string and returns a Jws<Claims> object (a signed JWT with its claims).<p>
     * 5. .getBody() extracts the Claims object from the parsed JWT, which is a map-like structure containing all the claims (including standard ones like "sub", "iat", "exp", and any custom ones).<p>
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * This Java method extractClaims provides a generic way to extract specific information from the claims of a JWT.
     * <p>
     * 1. It takes a JWT string (token) and a Function<Claims, T> called claimsResolver as input. The Function is a functional interface that accepts a Claims object and returns a value of type T.<p>
     * 2. final Claims claims = extractAllClaims(token); first calls the extractAllClaims method to get all the claims from the provided token.<p>
     * 3. return claimsResolver.apply(claims); then applies the provided claimsResolver function to the extracted Claims object. This function will define how to select and return a specific piece of information (of type T) from the claims.<p>
     */
    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * This Java method extractUserName is a specific implementation of the more general extractClaims method. It's designed to extract the username (which is typically stored in the "subject" claim) from a given JWT string (token).
     * <p>
     * It achieves this by calling the extractClaims method and providing a lambda expression Claims::getSubject as the claimsResolver. This lambda expression is equivalent to a function that takes a Claims object as input and returns the value associated with the "subject" key.
     */
    public String extractUserName(String token) {
        return extractClaims(token, Claims::getSubject);
    }

}
