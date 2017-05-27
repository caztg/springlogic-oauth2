package cn.springlogic.oauth2;

import com.fitcooker.app.BussinessException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
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

    @Autowired
    private ConsumerTokenServices consumerTokenServices;




    @RequestMapping(value = "/oauth/revoke-token", method = RequestMethod.GET)

    public ResponseEntity<Void> logout( HttpServletRequest request) throws BussinessException {
        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null) {
                String tokenValue = authHeader.replace("Bearer", "").trim();

                consumerTokenServices.revokeToken(tokenValue);
            }
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            throw new BussinessException("销毁token失败");
        }


    }
}