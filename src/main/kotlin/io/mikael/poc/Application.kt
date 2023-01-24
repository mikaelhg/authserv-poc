package io.mikael.poc

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@SpringBootApplication
@EnableWebSecurity
@Configuration
class Application {

	@Bean
	@Order(1)
	fun protocolFilterChain(http: HttpSecurity): SecurityFilterChain {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
		http
			.exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity> ->
				exceptions
					.authenticationEntryPoint(
						LoginUrlAuthenticationEntryPoint("/login")
					)
			}
			.oauth2ResourceServer { obj -> obj.jwt() }
			.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
			.oidc(Customizer.withDefaults())
		return http.build()
	}

	@Bean
	@Order(2)
	fun authenticationFilterChain(http: HttpSecurity): SecurityFilterChain {
		http
			.authorizeHttpRequests { authorize ->
				authorize.anyRequest().authenticated()
			}
			.formLogin(Customizer.withDefaults())
		return http.build()
	}

	@Bean
	fun userDetailsService(encoder: PasswordEncoder): UserDetailsService {
		val userDetails: UserDetails = User.builder()
			.passwordEncoder(encoder::encode)
			.username("james")
			.password("gosling")
			.roles("FOUNDER")
			.build()
		return InMemoryUserDetailsManager(userDetails)
	}

	@Bean
	fun passwordEncode() = BCryptPasswordEncoder()

	@Bean
	fun registeredClientRepository(): RegisteredClientRepository {
		val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId("id")
			.clientSecret("secret")
			.clientAuthenticationMethod(
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC
			)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.redirectUri(
				"http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc"
			)
			.redirectUri("http://127.0.0.1:8080/authorized")
			.scope(OidcScopes.OPENID)
			.scope(OidcScopes.PROFILE)
			.scope("message.read")
			.scope("message.write")
			.clientSettings(
				ClientSettings.builder()
					.requireAuthorizationConsent(true).build()
			)
			.build()
		return InMemoryRegisteredClientRepository(registeredClient)
	}

	@Bean
	fun authorizationServerSettings(): AuthorizationServerSettings {
		return AuthorizationServerSettings.builder().build()
	}

	@Bean
	fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
	}

	@Bean
	fun jwkSource(): JWKSource<SecurityContext> {
		val keyPair = generateRsaKey()
		val publicKey = keyPair.public as RSAPublicKey
		val privateKey = keyPair.private as RSAPrivateKey
		val rsaKey = RSAKey.Builder(publicKey)
			.privateKey(privateKey)
			.keyID(UUID.randomUUID().toString())
			.build()
		val jwkSet = JWKSet(rsaKey)
		return ImmutableJWKSet(jwkSet)
	}

	private fun generateRsaKey(): KeyPair {
		try {
			val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
			keyPairGenerator.initialize(2048)
			return keyPairGenerator.generateKeyPair()
		} catch (ex: Exception) {
			throw IllegalStateException(ex)
		}
	}

}

fun main(args: Array<String>) {
	runApplication<Application>(*args)
}
