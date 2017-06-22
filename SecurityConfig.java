package cn.springlogic.oauth2;

import cn.springlogic.user.jpa.entity.Role;
import cn.springlogic.user.jpa.entity.User;
import cn.springlogic.user.jpa.repository.RoleRepository;
import cn.springlogic.user.jpa.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

import java.util.*;

/**
 * Created by admin on 2017/4/12.
 */
@Configuration
class WebSecurityConfiguration extends GlobalAuthenticationConfigurerAdapter {


    @Autowired
    private UserRepository userRepository;

    private Collection<GrantedAuthority> getAuthorities(User user){
        List<GrantedAuthority> authList = new ArrayList<GrantedAuthority>();
        Set<Role> roles = user.getRoles();
       // List<Role> roles = user.getRoles();
        for (Role r:roles) {
            authList.add(new SimpleGrantedAuthority(r.getName()));
        }

        return authList;
    }

    /**
     * 设置用户密码的加密方式为MD5加密
     * @return

    @Bean
    public Md5PasswordEncoder passwordEncoder() {
        return new Md5PasswordEncoder();

    }
     */

    @Override
    public void init(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
        // .passwordE
        //auth.inMemoryAuthentication().withUser("user").password("user").roles("USER");
    }



    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

                User user = userRepository.findByUsername(username);


                if(user != null){
                    /**
                     * 返回一个 security.core.userdetails的User对象, 里面要设置
                     * 用户名 String
                     * 密码   String
                     * enabled    boolean
                     * accountNonExpired    boolean
                     * credentialsNonExpired  boolean
                     * accountNonLocked  boolean
                     * list   list
                     *    -> 可以自己写方法    Collection<GrantedAuthority> authList = getAuthorities();
                     *    类型是 Collection<GrantedAuthority>
                     *        /**
                     * 获取用户的角色权限,为了降低实验的难度，这里去掉了根据用户名获取角色的步骤(应该是从数据库里面查询的)
                     * @param
                     * @return
                     */


                   /*
                    return new org.springframework.security.core.userdetails.User(
                            user.getUsername(),
                            user.getPassword(),
                            true,
                            true,
                            true,
                            true,
                         // AuthorityUtils.createAuthorityList("ROLE_USER")  //  手动添加进角色
                            getAuthorities(user)  //根据用户拿出里面的角色

                    );
                    */
                    return new DiyUser(
                            user.getId(),
                            user.getNickName(),
                            user.getUsername(),
                            user.getPassword(),
                            true,
                            true,
                            true,
                            true,
                            // AuthorityUtils.createAuthorityList("ROLE_USER")  //  手动添加进角色
                            getAuthorities(user)  //根据用户拿出里面的角色

                    );
                } else {
                    throw new UsernameNotFoundException("could not find the user '"
                            + username + "'");
                }
            }
        };
    }


}

@Configuration
@EnableResourceServer
class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId("tonr").stateless(true);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http

                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
                .requestMatchers().antMatchers("/api/**")



                // 相关处理
                .and()
                .authorizeRequests()
                //.antMatchers("/se").access("#oauth2.hasScope('write')");
                .antMatchers("/api/basket:basket-disheses/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")//角色至少 含有 ROLE_USER才可以访问 (正常用户是拥有该角色,除非后台屏蔽)
                 .and()
                .authorizeRequests()
                .antMatchers("/api/article/publish").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.DELETE,"/api/social:publication/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers("/api/dishes:dishes-**/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers("/api/message:**/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/api/social:**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.DELETE,"/api/social:**/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.PATCH,"/api/user/forgetpwd").permitAll()
                .and()

                .authorizeRequests()
                .antMatchers(HttpMethod.PATCH,"/api/user/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")

                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/api/expressaddress/**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/api/address:**").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/api/vip:prizelog").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/api/vip:experiencetasklog").access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')");


                /*
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
                .requestMatchers().antMatchers("/sei")
                .and()
                .authorizeRequests()
                //.antMatchers("/se").access("#oauth2.hasScope('write')");
                .antMatchers("/sei").access("hasRole('ROLE_USER')");//角色含有 ROLE_USER就可以访问
              */

    }



}

@Configuration
@EnableAuthorizationServer
class OAuth2ServerConfig extends AuthorizationServerConfigurerAdapter {
    String applicationName = "tonr";
    @Autowired
    AuthenticationManagerBuilder authenticationManager;
    @Autowired
   private RoleRepository roleRepository;




    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
            throws Exception {

        endpoints.authenticationManager(new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication)
                    throws AuthenticationException {
                return authenticationManager.getOrBuild().authenticate(authentication);
            }
        });
              /*
             * .pathMapping("/oauth/authorize", "/oauth2/authorize")
             * .pathMapping("/oauth/token", "/oauth2/token");
             */
        // 以上的注释掉的是用来改变配置的
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        List<Role> roles = roleRepository.findAll();
        List<String> strs=new ArrayList<>();
        for (Role r:roles) {
             strs.add(r.getName());
        }
        String[] roleStrs = strs.toArray(new String[roles.size()]);
        ClientDetailsServiceBuilder<InMemoryClientDetailsServiceBuilder>.ClientBuilder clientBuilder = clients.inMemory().withClient(applicationName).accessTokenValiditySeconds(432000).refreshTokenValiditySeconds(864000)
                .authorizedGrantTypes("password", "authorization_code", "client_credentials", "refresh_token");

        clientBuilder.authorities(roleStrs).scopes("write").resourceIds(applicationName).secret("secret");


        /*
        // refreshTokenValiditySeconds = 2592000;       //refresh_token 的超时时间  默认2592000秒
        //accessTokenValiditySeconds = 10;             //access_token 的超时时间   默认12个小时 43200秒
        clients.inMemory().withClient(applicationName).accessTokenValiditySeconds(432000).refreshTokenValiditySeconds(864000)
                .authorizedGrantTypes("password", "authorization_code", "client_credentials","refresh_token")
                //.authorities("ROLE_USER")// 设置 角色
                .authorities("ROLE_USER").scopes("write").resourceIds(applicationName)
                .secret("secret");
                */

    }
}
