package foo.application.starter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootConfiguration
@EnableAutoConfiguration
@PropertySource("classpath:/app.properties")
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @RestController
    public static class Controller {
        @RequestMapping("/secure/user")
        public String secure(@AuthenticationPrincipal String user) {
            return null == user ? "null" : user;
        }

        @RequestMapping("/insecure/user")
        public String unsecure(@AuthenticationPrincipal String user) {
            return null == user ? "null" : user;
        }
    }

    @EnableResourceServer
    public static class SecurityConfig extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .antMatchers("/secure/**")
                        .authenticated()
                    .anyRequest()
                        .permitAll();
        }
    }
}
