
package com.zzy.security.config;

import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * security配置
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 构建AuthenticationManager
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // @formatter:off
//        auth
//            .authenticationProvider(usernameAndPasswordAuthenticationProvider)
//            .authenticationProvider(tokenAuthenticationProvider);
        // @formatter:on
    }

    /**
     * 1 配置Spring Security的Filter链 web.addSecurityFilterChainBuilder(securityFilterChainBuilder) 
     * 2 配置哪些东西不需要拦截
     */
    @Override
    public void configure(WebSecurity web) throws Exception {

        super.configure(web);
    }

    /**
     * 构建哪些东西需要拦截
     */
    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        // @formatter:off
//        http
//            .addFilterBefore(new AuthenticationFilter(authenticationManager()), BasicAuthenticationFilter.class)
//            .exceptionHandling()
//            .authenticationEntryPoint(unauthorizedEntryPoint())
//        .and()
//            .csrf()
//            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//        .and()
//            .formLogin()
//            .loginProcessingUrl("/anonymity/api/authentication")
//            .successHandler(authenticationSuccessHandler())
//            .failureHandler(authenticationFailureHandler())
//            .usernameParameter("j_username")
//            .passwordParameter("j_password")
//            .permitAll()
//        .and()
//            .logout()
//            .logoutUrl("/api/logout")
//            .logoutSuccessHandler(logoutSuccessHandler())
//            .deleteCookies("JSESSIONID", "XSRF-TOKEN", "token")
//            .permitAll()
//        .and()
//            .authorizeRequests()
//            .antMatchers("/anonymity/api/authenticate").permitAll()
//            .antMatchers("/api/**").authenticated()
//            .antMatchers("/api/admin/**").hasAuthority(AuthoritiesConstants.ADMIN);
        // @formatter:on
    }

    /**
     * 构建认证成功处理器。
     *
     * @return 认证成功处理器
     */
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> response.setStatus(HttpServletResponse.SC_OK);
    }

    /**
     * 构建认证失败处理器。
     *
     * @return 认证失败处理器
     */
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
    }

    /**
     * 构建未认证处理器。
     *
     * @return 未认证处理器
     */
    @Bean
    public AuthenticationEntryPoint unauthorizedEntryPoint() {
        return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
