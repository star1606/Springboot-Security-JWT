package com.cos.jwtex01.config.jwt;

import java.io.IOException;
import java.sql.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.dto.LoginRequestDto;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	
	private final AuthenticationManager authenticationManager;
	
	// Authentication 객체 만들어서 리턴 => 의존 : AutecnticationManager
	// 인증 요청시에 실행되는 함수 => /login 일때만. 
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		System.out.println("JwtAuthenticationFilter : 진입");
		// 1. reques에 있는 username과 password를 파싱해서 자바 object로 받기
		ObjectMapper om = new ObjectMapper();
		LoginRequestDto loginRequestDto = null;
		
		try {
			loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
		// 유저네임패스워드 토큰 생성
		UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(
						loginRequestDto.getUsername(),
						loginRequestDto.getPassword());
		
		// authentication() 함수가 호출되면 AuthenticationProvider가
		// UserDetailsService의 loadUserByUsername(토큰의 첫번째 파라미터를) 호출하고
		// UserDetails를 리턴받아서 토큰의 두번째 파라미터 (credential)과
		// UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면 
		// Authentication 객체를 만들어서 필터 체인으로 리턴해준다.
		
		// Tip : AuthenticationProvider의 디폴트 서비스는 userDetailService 타입
		// Tip : AuthenticationProvider의 디폴트 암호화 방식은 BCryptPasswordEncoder
		// 결론은 AuthenticationProvider에게 알려줄 필요 없음
		
		Authentication authentication = 
				authenticationManager.authenticate(authenticationToken);
		
		
		PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("Authentication : "+principalDetailis.getUser().getUsername());
		
		return authentication;// 리턴하면 sucessful 메소드로 탄다
	}

	//// JWT Token 생성해서 response에 담아주기
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();
		
		String jwtToken = JWT.create()
				.withSubject(principalDetailis.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+864000000))
				.withClaim("id", principalDetailis.getUser().getId())
				.withClaim("username", principalDetailis.getUser().getUsername())
				.sign(Algorithm.HMAC512("조익현"));
		
		response.addHeader("Authorization", "Bearer "+jwtToken);
	}
	
}
