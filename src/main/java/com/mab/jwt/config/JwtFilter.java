package com.mab.jwt.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mab.jwt.exception.JwtCustomException;
import com.mab.jwt.service.JwtProvider;
import com.mab.jwt.vo.JwtErrorCodes;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;

@Component
public class JwtFilter extends OncePerRequestFilter {

	private final Logger logger = LoggerFactory.getLogger(getClass());

	private String accessTokenName;

	private String insecureUrlPattern;

	private JwtProvider jwtProvider;

	public JwtFilter(JwtProvider jwtProvider, @Value("${jwt.accessToken.name}") String accessTokenName,
			@Value("${jwt.insecure.urlPattern}") String insecureUrlPattern) {
		this.jwtProvider = jwtProvider;
		this.accessTokenName = accessTokenName;
		this.insecureUrlPattern = insecureUrlPattern;
	}

	/**
	 * <B>History</B>
	 * <ul>
	 * <li>Date : 2019. 2. 15.
	 * <li>Developer : devmrko
	 * <li>reset SecurityContextHolder authentication
	 * </ul>
	 * 
	 */
	private void resetAuthenticationAfterRequest() {
		SecurityContextHolder.getContext().setAuthentication(null);
	}

	/**
	 * <B>History</B>
	 * <ul>
	 * <li>Date : 2019. 2. 15.
	 * <li>Developer : devmrko
	 * <li>apply authentication in SecurityContextHolder
	 * </ul>
	 * 
	 * @param authentication
	 */
	private void applyAuthenticationAfterRequest(Authentication authentication) {
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	/**
	 * <B>History</B>
	 * <ul>
	 * <li>Date : 2019. 2. 15.
	 * <li>Developer : devmrko
	 * <li>customize filter logic to apply JWT token validation
	 * </ul>
	 * 
	 * @param authentication
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain)
			throws ServletException, IOException {

		if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
			res.setHeader("Access-Control-Allow-Origin", "*");
			res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE");
			res.setHeader("Access-Control-Allow-Credentials", "true");
			res.setHeader("Access-Control-Allow-Headers",
					"Content-Type, Accept, X-Requested-With, remember-me, x-access-token");
			res.setHeader("Access-Control-Request-Headers", "x-access-token");
			res.setHeader("Access-Control-Expose-Headers", "Content-Length, Authorization");
		}

		try {
			String jwtStr = req.getHeader(accessTokenName);
			if (jwtStr == null) {
				JwtCustomException jwtCustomException = new JwtCustomException(
						JwtErrorCodes.CSC_WITHOUT_JWT,
						JwtErrorCodes.CSC_WITHOUT_JWT.toString());
				throw new Exception(JwtErrorCodes.CSC_WITHOUT_JWT.toString(), jwtCustomException);
			}

			if (StringUtils.hasText(jwtStr)) {
				this.jwtProvider.validateJwtToken(jwtStr);
				Authentication authentication = jwtProvider.getJwtAuthentication(jwtStr);
				this.jwtProvider.checkUrlByRole(req, authentication);
				this.applyAuthenticationAfterRequest(authentication);
			}
			this.resetAuthenticationAfterRequest();
			filterChain.doFilter(req, res);

		} catch (ExpiredJwtException ex) {
			logger.error("### ### ### - ExpiredJwtException: {}", ex.getMessage());
			// request.setAttribute("message", JwtErrorCodes.CSC_JWT_EXPIRED);
			res.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_JWT_EXPIRED.toString());

		} catch (MalformedJwtException ex) {
			logger.error("### ### ### - MalformedJwtException: {}", ex.getMessage());
			res.sendError(HttpServletResponse.SC_UNAUTHORIZED, JwtErrorCodes.CSC_BAD_TOKEN.toString());

		} catch (Exception ex) {
			Throwable t = ex.getCause();
			if (t != null) {
				logger.info("### ### ### - Exception - {}", t.getMessage());

				switch (t.getMessage()) {
				case "CSC_CANNOT_REFRESH":
					customSendError(res, JwtErrorCodes.CSC_CANNOT_REFRESH);
					break;
				case "CSC_BAD_CREDENTIALS":
					customSendError(res, JwtErrorCodes.CSC_BAD_CREDENTIALS);
					break;
				case "CSC_URL_FORBIDDEN":
					customSendError(res, JwtErrorCodes.CSC_URL_FORBIDDEN);
					break;
				case "CSC_UNAUTHORIZED":
					customSendError(res, JwtErrorCodes.CSC_UNAUTHORIZED);
					break;
				case "CSC_WITHOUT_JWT":
					customSendError(res, JwtErrorCodes.CSC_WITHOUT_JWT);
					break;
				}
				;
			} else {
				res.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
			}
		}

	}

	// filter에 사용하지 않을 url 패턴 설정
	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		String path = request.getServletPath();
		return path.startsWith(insecureUrlPattern);
	}

	/**
	 * <B>History</B>
	 * <ul>
	 * <li>Date : 2019. 2. 15.
	 * <li>Developer : devmrko
	 * <li>handle response when expected error is occurred
	 * </ul>
	 * 
	 * @param response
	 * @param jwtErrorCodes
	 * @throws IOException
	 */
	public void customSendError(HttpServletResponse response, JwtErrorCodes jwtErrorCodes) throws IOException {
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, jwtErrorCodes.toString());
	}

}
