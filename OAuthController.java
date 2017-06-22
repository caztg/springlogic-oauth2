package cn.springlogic.oauth2;

import com.fitcooker.app.BussinessException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by admin on 2017/5/9.
 */
@Controller
public class OAuthController {
    @Autowired
    private AuthorizationServerTokenServices authorizationServerTokenServices;
    //@Autowired
   // private AuthenticationUserDetailsService authenticationUserDetailsService;
    @Autowired
    private AuthorizationServerEndpointsConfiguration endpoints;



    @Autowired
    private ConsumerTokenServices consumerTokenServices;


    /**
     * 销毁token
     * @param request
     * @return
     * @throws BussinessException
     */

    @RequestMapping(value = "/oauth/revoke-token", method = RequestMethod.GET)

    public ResponseEntity<Void> logout( HttpServletRequest request) throws BussinessException {
        boolean b=false;
        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null) {
                String tokenValue = authHeader.replace("Bearer", "").trim();

                 b = consumerTokenServices.revokeToken(tokenValue);
            }
            if(b) {
                return ResponseEntity.ok().build();
            }else {
                throw new BussinessException("销毁token失败");
            }
        } catch (Exception e) {
            throw new BussinessException("销毁token失败");
        }


    }

    /**
     * 同上
     * @param request
     * @return
     * @throws BussinessException
     */
    @RequestMapping(value = "/2", method = RequestMethod.GET)

    public ResponseEntity<String> logout2( HttpServletRequest request) throws BussinessException {

        try {
            String authHeader = request.getHeader("Authorization");
            String a=null;
            if (authHeader != null) {
                String tokenValue = authHeader.replace("Bearer", "").trim();
                //拿出存在 内存MemoryTokenStore对象
                InMemoryTokenStore tokenStore=(InMemoryTokenStore) endpoints.getEndpointsConfigurer().getTokenStore();
                //根据 accesstoken 字符串获取 OAuth2AccessToken对象
                OAuth2AccessToken oAuth2AccessToken = tokenStore.readAccessToken(tokenValue);
                //根据 OAuth2AccessToken 对象 获取 OAuth2Authentication(保存了 用户信息等等)
                OAuth2Authentication oAuth2Authentication = tokenStore.readAuthentication(oAuth2AccessToken);
                // 获取 当前用户的 Authentication 对象
                Authentication userAuthentication = oAuth2Authentication.getUserAuthentication();
                // 里面的 Principal()就是 当前的 UserDetail对象 .
                DiyUser principal =(DiyUser) userAuthentication.getPrincipal();
                a=principal.getUserId()+"";

                tokenStore.removeAccessToken(tokenValue);

            }
            return ResponseEntity.ok(a);
        } catch (Exception e) {
            throw new BussinessException("销毁token失败");
        }


    }

    @RequestMapping(value = "/oauth/user", method = RequestMethod.GET)

    public ResponseEntity<Object> getUserInfoByToken( HttpServletRequest request) throws BussinessException {

        try {
            String authHeader = request.getHeader("Authorization");
            DiyUser principal=null;
            if (authHeader != null) {
                String tokenValue = authHeader.replace("Bearer", "").trim();
                //拿出存在 内存MemoryTokenStore对象
                InMemoryTokenStore tokenStore=(InMemoryTokenStore) endpoints.getEndpointsConfigurer().getTokenStore();
                //根据 accesstoken 字符串获取 OAuth2AccessToken对象
                OAuth2AccessToken oAuth2AccessToken = tokenStore.readAccessToken(tokenValue);
                //根据 OAuth2AccessToken 对象 获取 OAuth2Authentication(保存了 用户信息等等)
                OAuth2Authentication oAuth2Authentication = tokenStore.readAuthentication(oAuth2AccessToken);
                // 获取 当前用户的 Authentication 对象
                Authentication userAuthentication = oAuth2Authentication.getUserAuthentication();
                // 里面的 Principal()就是 当前的 UserDetail对象 .
                 principal =(DiyUser) userAuthentication.getPrincipal();

            }
            return ResponseEntity.ok(principal);
        } catch (Exception e) {
            throw new BussinessException("获取失败");
        }


    }

}