# Securing JWT by TOTP, meet the new JWTS
If you have landed here, so you are already interested in taking your application’s security to its next level and most probably you are already a loyal consumer of the “Json Web Token” as known as JWT. This article will introduce you to a brand new approach regarding the usage of JWT, which is the combination of the two very famous security mechanisms JWT and TOTP for the first time in their digital lives.

# Issue
The demand for a more secure application is a finite path which needs to be synchronized with the security exploits, as the Hackers are always one step ahead :)

The JWT has not been designed in order to carry any sensitive data like passwords, because the content of the JWT is easily decode-able

> Generate a JWT and visit [jwt.io](https://jwt.io/) then paste your token in the Debugger/Encoded section to see the content of the it

<blockquote class="embedly-card" data-card-controls="0"><h4><a href="https://en.wikipedia.org/wiki/Hash_function">Hash function - Wikipedia</a></h4><p>needs additional citations for verification .improve this article by adding citations to reliable sources. Unsourced material may be challenged and removed. (Learn how and when to remove this template message)</p></blockquote>

But what JWT is claiming is the “data integrity”, which means that after the issuance of the token, the data which the token is carrying can not be modified. this confidence is based on the usage of some hash algorithms to sign the data which is carrying, therefore when it’s being validated the hash values can be calculated again and if there is any miss match there, the token will be dropped as an invalid token.

## - Hash algorithms are not irreversible
While there are still some security experts using HASH algorithms to secure their applications because of its irreversible property, the hash algorithms are not as irreversible as they have been thought to be, to understand this claim better, let’s review some scenarios.
 
<blockquote class="embedly-card" data-card-controls="0"><h4><a href="https://en.wikipedia.org/wiki/MD5">MD5 - Wikipedia</a></h4><p>The MD5 message-digest algorithm is a widely used hash function producing a 128- bit hash value. Although MD5 was initially designed to be used as a cryptographic hash function, it has been found to suffer from extensive vulnerabilities. It can still be used as a checksum to verify data integrity, but only against unintentional corruption.</p></blockquote>

Let’s say [MD5](https://en.wikipedia.org/wiki/MD5) has been used to hash passwords in an application

```c#
MD5(“PASSWORD”) => 319f4d26e3c536b5dd871bb2c52e3178
```

off course there is no possible way (yet) to calculate “PASSWORD” from “319f4d26e3c536b5dd871bb2c52e3178” but if you have a good memory, by now, you know that “319f4d26e3c536b5dd871bb2c52e3178” is MD5 of “PASSWORD” so why should you calculate it when you can memorize it ?

you simply need to generate all the combinations of possible passwords to their MD5 equivalents and save it to a database like this

```c#
MD5(“PASSWORD”) => 319f4d26e3c536b5dd871bb2c52e3178
MD5(“password”) => 5f4dcc3b5aa765d61d8327deb882cf99
MD5(“pass”) => 1a1dc91c907325c69271ddf0c944bc72
.
.
.
```

It will take a very very long time to generate all the possible combinations of different passwords’ MD5 equivalents, but it needs to be done only once, right? because the MD5 value of the “PASSWORD” will always be “319f4d26e3c536b5dd871bb2c52e3178‘

> Remember, when something is possible to do , then the odds are it has been already done .

to see it for yourself check out one of the MD5 databases [here](https://md5decrypt.net/en/)

<blockquote class="embedly-card" data-card-controls="0"><h4><a href="https://md5decrypt.net/en/">Md5 Decrypt & Encrypt - More than 10.000.000.000 hashes</a></h4><p>Encrypt a word in Md5, or decrypt your hash by comparing it with our online decrypter containing 10,311,700,774 unique Md5 hashes for Free.</p></blockquote>

therefore 

> **A hash algorithm like MD5 or any other irreversible algorithm is not 
really “irreversible”, but “hard to reverse”.**

## - Master Keys on your server are calculate-able
Another way to figure out what’s behind the hashed data is to find out the Algorithm & Master_Key which has been used for the hashing of the data. In case of JWT, the algorithm is already on the table (read more here) therefore the only missing piece is the Master_Key, with the knowledge of both algorithm and master key one can generate unlimited valid JWTs instead of the authorized server. but the experts will always make sure that the key is located on a secure server and no one can access it.

While the Master_Key is being inaccessible, it is possible to brute force our way to re-generate it, to achieve this one needs to simply ask the server for a valid JWT like this

```c#
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOiJhZG1pbiIsImV4cCI6MTU1MzI0ODI4NSwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UifQ.
wtSuqFESQjlL0igRC8OsxMK6SZIcKguL73sI-GjTE8k
```
and then decode the contents of the above JWT like this

![](https://cdn-images-1.medium.com/max/800/1*l2BUf4Rov9EbF8H7lMBjVg.png "WT.io")

By having the contents and the algorithm of the JWT, one simple way will be to try all the possible combinations of the Master_Key to re-generate the same JWT and if enough processing power (super computer is preferred :) ) is available the Master_Key can be deciphered right on-time, before the expiration of the token.

> With Quantum computing on the way, the processing power will not be an issue in the early future

As it can be seen, despite of the processing expenses regarding to the hashed data deciphering or JWT’s Master_Key brute forcing, the rest is simple and achievable, therefore there is a need for a more secure version of the JWT, and that was my motivation for designing the JWTS or “Json Web Token Secure”.

But before getting into the JWTS let’s have a look at the normal JWT’s working process in action in order to have a better context.


# JWT

<blockquote class="embedly-card" data-card-controls="0"><h4><a href="https://jwt.io/introduction/">JWT.IO - JSON Web Tokens Introduction</a></h4><p>JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred between two parties. Learn more about them, how they work, when and why you should use JWTs.</p></blockquote>

Below a normal implementation of JWT can be seen
![](https://cdn-images-1.medium.com/max/800/1*pgxACJ0eqH7Bdqwhsq8B2Q.png)

And the code in C# for generating a JWT goes like this

```c#
var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MASTER_KEY"));
var signinCredentials = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
var tokeOptions = new JwtSecurityToken(
    issuer: "issuer",
    audience: "audience",
    claims: new List<Claim>()
    {
        new Claim(ClaimTypes.Role,"admin"),
    },
    expires: DateTime.UtcNow.AddMinutes(30),
    signingCredentials: signinCredentials
);
var tokenString = new JwtSecurityTokenHandler().WriteToken(tokeOptions);
```
And for validating it, it goes like this
```c#
var validationParameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidateAudience = true,
    ValidateLifetime = true,
    ValidateIssuerSigningKey = true,
    ValidIssuer = "issuer",
    ValidAudience = "audience",
    IssuerSigningKey =
        new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MASTER_KEY"))
};
var validator = new JwtSecurityTokenHandler();
//trying to parse the token s
var principal =
    validator.ValidateToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy5taWNyb3NvZnQuY29tL3dzLzIwMDgvMDYvaWRlbnRpdHkvY2xhaW1zL3JvbGUiOiJhZG1pbiIsImV4cCI6MTU1MzI0MjE4OSwiaXNzIjoiaXNzdWVyIiwiYXVkIjoiYXVkaWVuY2UifQ.mmlPrmXQKi87bMipXoS7ITvF6VjWQqiCHZbUDePoCfY", validationParameters, _);
var role= principal.Claims.First(z => z.Type == ClaimTypes.Role).Value;
if (role.Equals("admin"))
{   
    //do admin stuff
}
```

# TOTP
The JWTS is using “Time-Based One Time Password” to secure its tokens, so a little review regarding the TOTP is necessary.

<blockquote class="embedly-card" data-card-controls="0"><h4><a href="https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm">Time-based One-time Password algorithm - Wikipedia</a></h4><p>The Time-based One-Time Password algorithm ( TOTP) is an extension of the HMAC-based One-time Password algorithm (HOTP) generating a one-time password by instead taking uniqueness from the current time.</p></blockquote>

The TOTP’s default duration is 30 seconds which means after dividing the total of “the seconds from UNIX epoch(1970–01–01 00:00:00) till now in UTC timezone” into “30 second chunks” calculation of the number of the 30 seconds iterations will be possible, then the number of the iterations will be passed to the TotpHash function to generate a 6 digits code which will be valid around 30 seconds afterwards.

```c#
public int Generate(string accountSecretKey)
{
    return TotpHash(accountSecretKey, GetCurrentCounter());
}
private long GetCurrentCounter()
{
    return (long) (DateTime.UtcNow - _unixEpoch).TotalSeconds / 30L;
}

private static int TotpHash(string secret, long iterationNumber, int digits = 6)
{
    return TotpHash(Encoding.UTF8.GetBytes(secret), iterationNumber, digits);
}
private static int TotpHash(byte[] key, long iterationNumber, int digits = 6)
{
    var bytes = BitConverter.GetBytes(iterationNumber);
    if (BitConverter.IsLittleEndian)
        Array.Reverse((Array) bytes);
    var hash = new HMACSHA1(key).ComputeHash(bytes);
    var index = hash[hash.Length - 1] & 15;
    return ((hash[index] & sbyte.MaxValue) << 24 | hash[index + 1] << 16 |
            hash[index + 2] << 8 | hash[index + 3]) % (int) Math.Pow(10.0, digits);
}
```
so with a basic understanding of the JWT and TOTP, it’s time to dive into the “Json Web Token Secure” as it will be known as “JWTS”

# Json Web Token Secure (JWTS)
Have you ever wondered to issue a JWT with a master key which even your application is not aware of it ? JWTS is an algorithm which by combining TOTP with JWT make the ultimate security of a JWT possible.

In a nutshell JWTS works as follows
![](https://cdn-images-1.medium.com/max/800/1*bUbrfNq8iyB3t7A4TcUcKw.png)

As it can be seen the JWTS is a combination of JWT and “Time-Based One Time Password” the idea behind it to create a token while no one is aware of its signing KEY, which have been used in the hashing process of the JWT. therefore even if the hackers successfully figure out the KEY of the token the next token is going to use a different KEY

## Example

The example below illustrates a scenario which the client will try to obtain two JWT from the server in two different moments of time for the same user, the JWT is carrying the same data.

![](https://cdn-images-1.medium.com/max/800/1*vQwYBF5SZBjCrQA4apu-dw.png)

Retrieving the JWT seams pretty straight forward, the algorithm simply uses the TOTP algorithm to generate a time-based code and then use it to sign the token with it, but the question which remains will be, how this token can be validated, while the exact KEY which it has been signed with is unknown? and the answer is : we will brute force it :)

# Solution
![](https://cdn-images-1.medium.com/max/800/1*6fRdEWDZVF5iqLm0k9dvxQ.png)

The token has been signed by the TOTP key, which is changing every 30 seconds, therefore on validating it the TOTP algorithm will generate a different code because the application will be at different moment in time but the beauty of it is that the codes which has been generated in the past can be regenerated in the future, for instance it is possible to regenerate a code which has been generated by the TOTP algorithm at 1 year ago, 1st of January 00:00:00.

So far, it is possible to re-generate the TOTP key for any moment of the time moreover the application knows the duration of the token’s validity, in result the JWTS algorithm only needs to re-generate all the codes from “now minus the token’s validity duration” till 1 minute later (for covering any over lapses), with that data in hand, JWTS will try each one of the regenerated codes as the JWT’s Master Key to decode the token , and if any of the codes results in success, thus the token has been signed by the authorized server belong to our project.

I have designed the JWTS for a kind of JWT applications with a short token validity , because by increasing the validity of the token the number of the codes, which the algorithm needs to try to validate will increase as well, moreover this process needs to be done for each request, so i recommend to use it carefully :) But if you need to use the JWTS for a token with a long validity, it is possible to change the number of the codes by changing the number of TOTP’ iterations, which means the TOTP algorithm will generate for example for every 10 minutes one code instead of every 30 seconds, consequently the security of the token will decrease, so it is a challenge between the security intensity and the processing power, which the best judge of that will be the software architecture of the application.

In summary, if you are looking for a method to issue a token with a KEY that even you are not aware of it, takes the next step and use the JWTS algorithm, furthermore if you got interested you can assist me in implementing the JWTS for other platforms :)

you can find the C# implementation of JWTS [here](https://github.com/AliTabryzy/JWTS/blob/master/dotnet/JWTS.NET/JWTS/JWTS.cs)

Happy coding :)
