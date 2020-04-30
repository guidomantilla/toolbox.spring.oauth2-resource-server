package toolbox.spring.oauth2.resource.server.ws;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceWs {

    @GetMapping("/admins")
    @PreAuthorize("hasAuthority('role_admin')")
    @ResponseBody
    public OAuth2Authentication context() {

        return (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
    }

    @GetMapping("/users")
    @PreAuthorize("hasAnyAuthority('role_admin','role_user')")
    @ResponseBody
    public OAuth2Authentication secured() {

        return (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
    }

    @GetMapping("/common")
    public String general() {
        return "common api success";
    }
}
