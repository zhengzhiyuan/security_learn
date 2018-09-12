
package com.zzy.security.security.filter;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.util.Optional;

import javax.security.sasl.AuthenticationException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.GenericFilterBean;

/**
 * 对token进行验证
 */
public class TokenFilter extends GenericFilterBean {

    private final Logger logger = getLogger(getClass());

    private AuthenticationManager authenticationManager;

    public TokenFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                Optional<String> token = getToken(httpRequest);
                if (token.isPresent()) {
                    processTokenAuthentication(token);
                }
            }
            logger.debug("AuthenticationFilter is passing request down the filter chain");
            chain.doFilter(request, response);

        } catch (InternalAuthenticationServiceException ex) {
            SecurityContextHolder.clearContext();
            logger.error("Internal authentication service exception", ex);
            httpResponse.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (AuthenticationException | BadCredentialsException ex) {
            SecurityContextHolder.clearContext();
            httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
        }
    }

    /**
     * 进行token验证
     * 
     * @param token
     */
    private void processTokenAuthentication(Optional<String> token) {
        PreAuthenticatedAuthenticationToken requestAuthentication = new PreAuthenticatedAuthenticationToken(token, null);
        Authentication responseAuthentication = authenticationManager.authenticate(requestAuthentication);
        if (responseAuthentication == null || !responseAuthentication.isAuthenticated()) {
            throw new InternalAuthenticationServiceException("Unable to authenticate Domain Account for provided credentials");
        }
        SecurityContextHolder.getContext().setAuthentication(responseAuthentication);
    }

    private Optional<String> getToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        String token = null;
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("token")) {
                    token = cookie.getValue();
                    break;
                }
            }
        }

        return Optional.ofNullable(token);
    }
}
