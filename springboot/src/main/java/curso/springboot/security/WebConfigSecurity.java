package curso.springboot.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebConfigSecurity extends WebSecurityConfigurerAdapter{

	@Autowired
	private ImplementacaoDetailsService implementacaoDetailsService;
	
	@Override //Configura as solicitações de acesso por http 
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf()
		.disable() // Desativa as configurações padrão de memória
		.authorizeRequests() // Permite restringir acessos
		.antMatchers(HttpMethod.GET, "/").permitAll() //Qualquer usuário acessa a pagina inicial
		.antMatchers(HttpMethod.GET, "/cadastropessoa").hasAnyRole("ADMIN")
		.anyRequest().authenticated()
		.and().formLogin().permitAll() //Permite qualquer usuário
		.loginPage("/login") //Pagina de login customizada
		.defaultSuccessUrl("/cadastropessoa")//Pagina de login customizada
		.failureUrl("/login?error=true")//Pagina de login customizada
		.and().logout().logoutSuccessUrl("/login")//Pagina de login customizada  //Mapea a url de logout e inválida usuário autenticado 
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
	}
	
	@Override// Cria autenticação do usuário com o banco de dados ou em memória
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
		auth.userDetailsService(implementacaoDetailsService)
		.passwordEncoder(new  BCryptPasswordEncoder());
		
		/* autenticação em memória
		 * 
			auth.inMemoryAuthentication().passwordEncoder(new  BCryptPasswordEncoder())
			.withUser("admin")
			.password("$2a$10$MvwXKj7lvtuoIGdJ2zLt1OVmbrcPGQQSMRSjqedaOKjWtWMBFbt/a")
			.roles("ADMIN");
		*/
	}
	
	@Override // ignora URLS especificas
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/springboot/src/main/resources/static/materialize/**");
	}
	
}
