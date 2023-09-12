# Spring Security with JWT
Hello everyone! This guide will walk you through setting up Spring Security with JWT support for your RESTful Spring Boot application.

## Step 1: Installing Dependencies
Before we start, please install the required Spring Security and OAuth2 Resource Server dependencies by pasting this code snippet into your `pom.xml` file.

*pom.xml*
```xml
<!-- ... -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>4.4.0</version>
</dependency>
<!-- ... -->
```

## Step 2: The User Model and Repository
We will first need to create a `User` model and repository.

*User.java*
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    private Integer id;
    private String username;
    private String password;
    // ...
}
```

*UserRepository.java*
```java
@Repository
public class UserRepository {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public User getUserById(Integer id) {
        // ...
    }

    public User getUserByUsername(String username) {
        // ...
    }

    // ...
}
```

## Step 3: Creating the UserPrincipal model
Additionally, we will need to create another model related to `User` which will implement the `UserDetails` interface.

*UserPrincipal.java*
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserPrincipal implements UserDetails {
    private User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.stream(user.getRoles().split(","))
                .map(role -> new SimpleGrantedAuthority(role))
                .toList();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return user != null;
    }

    @Override
    public boolean isAccountNonLocked() {
        return user != null;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return user != null;
    }

    @Override
    public boolean isEnabled() {
        return user != null;
    }
}
```

This model is similar to the `User` model, but with authentication-specific methods.

## Step 4: Creating an Authentication Service
Now that we have installed our required dependencies, we will be creating an authentication service to handle authentication tasks for our application. Implement the `UserDetailsService` interface and override its methods and add the following code within the overridden method's body.

*AuthService.java*
```java
@Service
public class AuthService implements UserDetailsService {
    @Autowired
    private UserRepository userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepo.getUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("Username not found!");
        }
        return new UserPrincipal(user);
    }
}
```

The `loadUserByUsername` method is essentially attempting to retrieve a record from your MySQL database based on the username that was fed in as an argument. We will dive deeper into implementing the controller to handle this in the subsequent steps.

## Step 5: Generating Public and Private Keys
In order to use JWT, we will need to generate a secret HS256 key that we will pass in as an environment variable. Visit https://jwt-keys.21no.de/, select HS256 (64 bytes) and generate a key.

After you have generated your keys, move them into your `/resources` folder and add these two lines in `application.properties`:

*application.properties*
```yml
jwt.key.secret=<YOUR GENERATED HS256 KEY HERE>
```

This will let Spring Boot know where your keys are for the next step.


## Step 6: Overriding the Default Configuration
With `AuthService` created, we can start creating a custom configuration file to set up Spring Security to authenticate users with stored credentials from your MySQL database.

Create a new configuration file named `SecurityConfig.java`, preferably in your `configs` folder.

*SecurityConfig.java*
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Autowired
    private AuthService authSvc;

    @Value("${jwt.key.secret}")
    private String secretKey;

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withSecretKey(new SecretKeySpec(secretKey.getBytes(), "HmacSHA256")).build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth ->
                        auth.requestMatchers("INSERT AUTH ENDPOINT PATH HERE").permitAll()
                                .anyRequest().authenticated()
                )
                .userDetailsService(authService)
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### An explanation for each method will be provided in the near future.

## Step 7: Creating a Token Service
Next, we will need to create a token service to handle our JWTs. These tokens will be generated through this service.

*TokenService.java*
```java
@Service
public class SecurityTokenService {
    @Value("${jwt.key.secret}")
    private String secretKey;
    public String generateToken(Authentication auth) {
        UserPrincipal userPrincipal = (UserPrincipal) auth.getPrincipal();
        Instant now = Instant.now();
        String scope = auth.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        return JWT.create()
                .withIssuer("Zapit")
                .withIssuedAt(now)
                .withSubject(String.valueOf(userPrincipal.getUser().getId()))
                .withExpiresAt(now.plus(1, ChronoUnit.HOURS))
                .withClaim("name", auth.getName())
                .withClaim("scope", scope)
                .sign(Algorithm.HMAC256(secretKey));
    }
}
```

### An explanation for each method will be provided in the near future.

## Step 8: Exposing Endpoints with a Controller
Finally, you will need to create a new controller or modify an existing one to handle your authentication endpoints. In this case, we will be creating a new controller.

*AuthController.java*
```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private UserService userSvc;
    @Autowired
    private TokenService tokenSvc;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) {
        // ...
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(Authentication auth) {
       String token = securityTokenService.generateToken(auth);
       return ResponseEntity.ofNullable(token);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout() {
        // ...
    }
}
```

Congratulations! You have successfully implemented Spring Security with JWT support in your application.
