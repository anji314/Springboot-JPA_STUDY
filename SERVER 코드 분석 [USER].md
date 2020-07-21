## SERVER 코드 분석 [USER]


-------------------------------------------------



#### 1) UserAuthController  (User/controller/UserController.java)

```java
 @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationResponse> authenticateUser(@Valid @RequestBody LoginDto loginDto) {
        System.out.println("받아온 아디랑 비밀번호 : "+loginDto.getUserId() + loginDto.getPassword() );
        return ResponseEntity.ok(this.userRegisterService.login(loginDto.getUserId(), loginDto.getPassword()));

    }
```

 - **login 매핑** : @PostMapping("/login")
 -  #### **JwtAuthenticationResponse** 
	
	- JWT(Json Web Token) : 정보를 안전하게 전송하기 위해 정의된 공개 표준(RFC 7519)
	- JWT 특징 
		1. self-contained(자가수용적) : JWT 자체적으로 필요한 모든 정보를 포함. 헤더 정보와, 실제 전달할 데이터, 검증 할 수있는 서명 데이터를 모두 포함한고 있다. 
		2. 신뢰할수 있다. :디지철 서명에 의해 검증할수있으며 신뢰 할 수 있다. 비밀 값을 사용하는 HMAC알고리즘이나 RDS or ECDSA와 같은 공개키,개인키 쌍으로 서명 된다.
	- 사용 이유
		1. 보안 이슈: 사용자가 자신의 비밀 값으로 서버에 로그인 하게 되면, 서버는 JWT를 리턴한다. token을 인증 값으로 사용하게 되면 기존 쿠키/세션을 사용하는 방식보다 많은 보안 이슈를 막을 수 있다. 서버는 GUI로부터 받은 JWT가 유효할 경우, resouce를 사용하도록 허용한다. 또한 JWT는 쿠키를 사용하지 않기 때문에, **Cross-Origin Resource Sharing (CORS) 이슈가 발생하지 않는다.**
		2. 데이터 용량: JWT는 기존의 XML보다 덜 복잡하고 인코딩 된 사이즈가 작습니다. 따라서 HTTP와 HTML 환경에서 사용하기 좋다.
		3. 사용성: JSON parser는 대부분의 프로그래밍이 지원하기 때문에 XML을 사용하는 SAML 보다 만들기 쉽다.
	- 구조
		- 3개의 파트가 dot(.)에 의해 구분 된다.
		
		  ```  
		  XXXX(==header).YYYY(==payload).ZZZZ(==signature)
		  ```
		1. Header
			- token의 type 과 서명에 사용된 알고리즘 으로 구성.
			
			  ```  http
			  { 
			  "alg" : "HS256", 
			  "typ" : "JWT" 
			  }
			  ```
			
	2. Payload
		- Claims(클레임)을 포함한다. => Claims : 객체나 추가적인 데이터
			-유형 3가지
				1) 등록된 클레임 ( Registered claims )
				
			> 이미 정의된 클레임들로 무조건 따라야 하는 것은 아니지만 권장하고 있다.대표적인 몇 가지 예를 들자면 iss (issuer, 토큰 발행자), exp (expiration time, 토큰 만료시간), sub (subject, 토큰 제목), aud(audience, 토큰 대상자) 와 같은 클레임들이 있고. 클레임의 이름은 compact를 위해 3글자로 사용하고 있다.
			
				2) 공개된 클레임 ( Public claims )
				
				>JWT를 사용하는 사람들에 의해 정의되는 클레임으로, 클레임 충돌을 피하기 위해서 IANA JSON Web Token Registry 에 정의하거나 URI 형식으로 정의해야 한다.
				
				3) 비공개 클레임 ( Private claims )
				
				> GUI, 서버, 그 외 모듈간에 협의한 클레임.
			
			- Payload의 예
			
			```http
			 { 
			 "sub" : "1234567890" , 
			 "name" : "John Doe" , 
			 "admin" : true 
			 }
			```
			
			 => 이 데이터가 Base64 인코딩 되어 두 번째 파트에 들어가게 된다..
			
		3. Signature(서명) 
		
		  -  암호 알고리즘으로 HMAC SHA256 알고리즘을 쓴다고 가정하면 서명을 만들기 위해 아래 공식을 사용한다.
		  - ex) HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload),secret)
		  -  이  서명은 메세지가 중간에 변경되지 않았음을 검증한다. == JWT를 보낸 사람이 신뢰할수있는 대상이라는 것을 알 수 있다.
		
	- 참고
		- https://medium.com/sjk5766/jwt-json-web-token-%EC%86%8C%EA%B0%9C-49e211c65b45
		- https://www.iana.org/assignments/jwt/jwt.xhtml
		- https://jwt.io/#debugger-io



 - #### ResponseEntity
	
	- Spring Framework에서 제공하는 클래스 중 **HttpEntity라는 클래스**가 존재한다. HTTP요청(Request)또는 응답(Response)에 해당하는 HttpHeader와 HttpBody를 포함하는 클래스인데, **이 클래스를 상속받아 구현한 클래스**가 RequestEntity와 **ResponseEntity**이다.
	
	- **즉 ResponseEntity는 사용자의 HttpRequest에 대한 응답 데이터를 포함하는 클래스이다.**(HttpStatus,HttpHeaders,HttpBody를 포함.)
	
	- **Restful API에서  return type으로 사용되고 있는 ResponseEntity.**
	
	- ResponseEntity는 @ResponseBody 어노테이션과 같은 의미로, ResponseEntity를 return type으로 지정하면 JSON(default)또는 Xml Format으로 나타난다.
	
	- 해당 메소드를 통해 작성하면 status -> header -> body 순으로 자동을 작성된다.
		=> http응답에 사용될 데이터 종류
			1) Status 	 : ex) ok() ==200응답 데이터
			2) Header   : header()메소드를 사용
			3) Body   : body()메소드를 이용하여 body를 작성할수있으며, 매게변수로는 응답할 데이터를 담아준면 된다. body()메소드를 사용하게 되면 ResponseEntity가 생성된다.
		
		
		
	- 참고
		
		- https://devfunny.tistory.com/321



------------------------------------------------



#### 2) UserRegisterService (user/service/UserRegisterService)

- **@RequiredArgsConstructor(onConstructor = @__(@Autowired))** : 의존성 주입

  #### [Spring Security Architecture]

  - 스프링 시큐리티에서는 "인증"과 "권한"을 분리하여 체크할 수 있도록 구조를 만들었다.
  - **Authentication(인증)**: 'A'라고 주장하는 주체(user,subject,principal)가 'A'가 맞는지 확인 하는 것
  	- 코드에서 Authentication : 인증과정에서 사용되는 핵심 객체  ->  ID/PASSWORD, JWT, OAuth 등 여러 방식으로 인증에 필요한 값이 전달되는데 이것을 하나의 인터페이스로 받아 수행하도록 추상화 하는 역할의 인터페이스다.
  - **Authorization(권한)** :특정 자원에 대한 권한이 있는지 확인 하는 것.
  	- 프로세스 상 신분 "인증"을 거치고 신분 인증이 되었으면 권한이 있는지 확인 후, 서버자원에 대해서 접근할 수있게 되는 순서다.
  	- 애플리케이션에서 이권한 과정은 굉장히 여러번 일어난다.   ex) id/password ,공인 인증서, 지문 등으로 로그인을 하는것은 '인증'에 해당한다.
  - **Credential(증명서)** : 인증 과정 중, 주체가 본인을 인증하기 위해 서버에 제공하는 것. (ID, Password 같은 것)

  - 요청에 대한 인증은 **UsernamePasswordAuthenticationFilter**가 담당한다.
    - Filter 동작 코드 (예시)
```java
public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) 
throws AuthenticationException { 
if (this.postOnly && !request.getMethod().equals("POST")) { 
throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod()); 
} else { 
String username = this.obtainUsername(request); 
String password = this.obtainPassword(request); 
if (username == null) { 
username = ""; 
}
if (password == null) { 
password = ""; 
} 
username = username.trim(); 
UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password); this.setDetails(request, authRequest); 
return this.getAuthenticationManager().authenticate(authRequest); 
} 
}		
```
- **UsernamePasswordAuthenticationFilter 클래스 내의 attemptAuthentication(request, response) 메서드를 보면, 요청으로부터 username과 password를 얻어오고 그 값으로 UsernamePasswordAuthenticationToken(Authentication)을 생성**한다. 
  그 다음에 참조하고 있던 **AuthenticationManager(구현체인 ProviderManager)에게 인증을 진행하도록 위임**한다.

- **UsernamePasswordAuthenticationToken 은 Authentication 인터페이스의 구현체**이다. 참고로 **Authentication(Interface)을 구현한 구현체여야만 AuthenticationManager에서 인증 과정을 수행할 수 있다.**

			- **UsernamePasswordAuthenticationToken 같은 경우에는 인증 받을 때에는 아이디가 전달되며, 인증받은 후에 DB에서 받은 객체로 변경된다.**
		=> 스프링 시큐리티를 이용하는 커스텀한 인증 절차를 만드려면 어떻게 해야할까?
			→ **UsernamePasswordAuthenticationFilter와 유사한 커스텀 필터를 만들고, 그 필터내에서 Authentication 인터페이스를 구현한 커스텀 클래스의 객체(토큰)를 만들어서 AuthenticationManager에 인증해달라고 던져주면 된다.**

```java
@Slf4j
@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class UserRegisterService {
    @NonNull
    private UserRepository userRepository;

    @NonNull
    private AuthenticationManager authenticationManager;

    @NonNull
    private JwtTokenProvider tokenProvider;

    public JwtAuthenticationResponse login(String userId, String password) {
        Authentication authentication = null;
        UserPrincipal userPrincipal = null;

        try {
            authentication = this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userId, password)
            );
```




- #### **AuthenticationManager > ProviderManager > AuthenticationProvider**

   **1) AuthenticationManager(interface)**	

     - Authentication 객체를 받아 인증하고 인증되었다면 인증된 Authentication 객체를 돌려주는 메서드를 구현하도록 하는 인터페이스다.
        - 이 메서드를 통해 인증되면 isAuthenticated(boolean)값을 TRUE로 바꿔준다

   **2) ProviderManager(Class)**

   - **AuthenticationManager의 구현체**로 스프링에서 인증을 담당하는 클래스로 볼 수 있다.(스프링 시큐리티가 생성하고 등록하고 관리하는 스프링 빈이므로 직접 구현할 필요가 없다.)
   - 직접 인증 과정을 진행하는 것이 아니라 멤버 변수로 가지고 있는 **AuthenticationProvider들에게 인증을 위임처리하고** 그 중에 하나의 **AuthenticationProvier객체(명확하게는 AuthenticationProvider를 구현한 클래스)가 인증과정을 거쳐서 인증에 성공하면 요청에 대해서 ProviderManager가 인증이 되었다고 알려주는 방식.**
   - 인증이 되었다고 알려주는 건 AuthenticationManager 인터페이스의 메서드인 authenticate() 메서드의 리턴 값인 Authentication객체 안에 인증 값을 넣어주는 것으로 처리한다

   

   **3) AthenticationProvider (Interface)**

   - authenticate(Authentication):Authentication → 앞서 AuthenticationManager에서 봤던 메서드와 똑같은 메서드로 **인증과정이 이 메서드를 통해 진행된다.**
   - supports(Class<?>):boolean  -> 앞에서 필터에서 보내준 Authentication 객체를 이 AuthenticationProvider가 인증 가능한 클래스인지 확인하는 메서드다.
   - UsernamePasswordAuthenticationToken이 ProviderManager에 도착한다면 ProviderManager는 자기가 갖고 있는 AuthenticationProvider 목록을 순회하면서 '너가 이거 해결해줄 수 있어?' 하고 물어보고(supports()) 해결 가능하다고 TRUE를 리턴해주는 AuthenticationProvider에게 authenticate() 메서드를 실행한다. (아래에 ProviderManager.class 내의 authenticate() 메서드를 가져왔으니 앞서 말한 동작을 확인해보면 도움될 것이다.)



#### [중간 흐름 정리]

1. 처음 UsernamePasswordAuthenticationFilter가 요청을 가로채 UsernamePasswordAuthenticationToken 객체를 AuthenticationManager에게 넘긴다.
2. 실제로는 AuthenticationManager Interface를 구현한 ProviderManager에게 넘겨진 것이다.
3. ProviderManager는 여러 AthenticationProvider들을 순회하면서 UsernamePasswordAuthenticationToken을 처리해줄 AuthenticationProvider를 찾는다.
4.  해당 객체를 찾으면 인증을 요청한다.



=> AuthenticationProvider은 인터페이스이므로 이 인터페이스를 구현한 클래스를 만들어 ProviderManager가 클래스 객체에게 인증을 위임하도록 하면, 직접 구현한 클래스가 인증처리를 하게된다.



- #### Authentication Provider  =>깃 소스에선 보이지않음.

  - 이곳에서 인증이 일어난다.
  - 핵심은 Authentication객체로부터 인증에 필요한 정보(Id,Password)를 받아오고, **UserDetailService 인터페이스를 구현한 객체 (CustomUserDetailService)로 부터 DB에 저장된 유저 정보를 받아온 후**, password를 비교하고 인증 완료되면 인증 완료된 Authetication객체를 리턴한다. 





- #### UserDetailService (CustomUserDetailService가 상속 받는다.)

  - 구현 예시(UserDetailService)

    ```java
    Service public class CustomUserDetailsService implements UserDetailsService { @Autowired private UserRepository userRepository; 
    //...생략 
    @Override 
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { 
    return userRepository.findByUsername(username).orElseThrow(()->new UsernameNotFoundException("Username not found '"+ username + "'")); 
    } 
    }
    ```

  - 구현 예시(UserRepository)

    => **UserRepositroty는 DB에 유저 정보를 가져오는 JPA구현체**이다.

    ```java
    public interface UserRepository extends JpaRepository<User, Long> { 
    Optional<User> findByUsername(String username); 
    }
    ```

    

  - #### CustomUserDetailService.java(깃 소스: _config/security/CustomUserDetailsService.java)

    => 여기서는 **private UserService userService;** 를 호출하여 이 클래스에서 UserRepository를 사용해 DB에서 유저정보를 가져온다.

  ```
  @Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class CustomUserDetailsService implements UserDetailsService {
    @NonNull
    private UserService userService;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String userId) {
        User user = this.userService.findByUserId(userId);

        return new UserPrincipal(user.getUserNo().getId(),
                user.getUserId(), user.getPassword(), user.getRoles(), !user.getLocked(), user.checkActiveUser());
    }
}
  ```
  
  
  
- #### AuthenticationProvider 추가하기

  - 직접 작성한 인증시스템인 CustomAuthenticationProvider를 ProviderManager가 알 수 있게 ProviderManager에게 등록하면된다.

```java
@Configuration 
@EnableWebSecurity 
public class SecurityConfig extends WebSecurityConfigurerAdapter { 
@Autowired 
private CustomAuthenticationProvider authProvider; 
@Override 
protected void configure(AuthenticationManagerBuilder auth) throws Exception { auth.authenticationProvider(authProvider); 
} 
@Override 
protected void configure(HttpSecurity http) throws Exception { http.authorizeRequests().anyRequest().authenticated() .and().httpBasic(); 
} 
}
```

=> 해당 부분은 깃소스에 없다....



​																																															-~2020.07.15 작성 완료-

-----------------------------------------------------------



### 3)UserRepository

-> 추가할 예정.

















