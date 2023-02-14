package com.practice.jwttoken.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;
import lombok.Value;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * packageName    : com.practice.jwttoken.token fileName       : JwtTokenProvider author         :
 * SSAFY date           : 2023-02-10 description    : ===========================================================
 * DATE              AUTHOR             NOTE -----------------------------------------------------------
 * 2023-02-10        SSAFY       최초 생성
 */
public class TokenProvider implements InitializingBean {

    private String secret;                               // 비밀키에 해당하는 문자열
    private long tokenValidationTime;                    // 토큰의 유효시간
    private final String AUTHORITIES_KEY = "planit";     // 추후에 권한을 얻기 위한 키로 사용될 문자열
    private Key key;                                     // 토큰을 암호화하는데 사용


    // application.yml 파일에 선언해 주었던 값들을 가져와서 해당 변수에 대입
    public TokenProvider(
        @Value("${jwt.secret}") String secret,
        @Value("${jwt.token-validity-in-seconds}") long tokenValidationTime) {
        this.secret = secret;
        this.tokenValidationTime = tokenValidationTime * 1000;
    }


    // Bean이 생성후 의존성 주입을 받은 후에 해당 메소드가 실행됨
    
    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] keyBytes = Decoders.BASE64.decode(secret);  // 비밀키를 BASE64 방식을 통하여 암호화 진행
        this.key = Keys.hmacShaKeyFor(keyBytes);           // 비밀키 만들어서 key에 대입
    }

    
    // 토큰 생성
    private String createToken(Authentication authentication) {
        String authorities = authentication.getAuthorities()  // Authentication 객체가 가지고 있는 권한 정보를 문자열로 변환
            .stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        Date date = new Date();
        long now = date.getTime();  // 현재 시간을 얻어옴
        Date tokenExpiration = new Date(now + this.tokenValidationTime);

        // 클레임
        // 기본정보
        Claims claims = Jwts.claims()
            .setSubject(authentication.getName())  // 사용자의 이름
            .setIssuedAt(date)                     // 발행시간
            .setExpiration(tokenExpiration);       // 만료시간
        // 개인정보
//        claims.put("userId", userId)

        return Jwts.builder()
            .setHeaderParam("type", "jwt")
            .setClaims(claims)                         // payload에 담길 데이터
            .signWith(SignatureAlgorithm.HS512, key)   // 서명 알고리즙과 비밀키
            .compact();
    }


    // 토큰을 매개변수로 받아서 토큰에 담긴 정보를 이용해 Authentication 객체를 리턴
    public Claims getTokenContents(String token) {
        Claims claims = Jwts.parser()  //
            .setSigningKey(key)        // 검색된 JWS 디지털 서명을 확인하는 데 사용되는 서명 키를 설정
            .parseClaimsJws(token)     // 빌더의 현재 구성 상태를 기반으로 지정된 압축 직렬화된 JWT 문자열을 구문 분석하고 서명되지 않은 일반 텍스트 JWT 인스턴스 결과를 반환
            .getBody();
        return claims;
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(this.key).parseClaimsJws(token).getBody()
        }
    }
}
