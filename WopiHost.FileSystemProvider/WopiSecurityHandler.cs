using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using WopiHost.Abstractions;

namespace WopiHost.FileSystemProvider
{
    /// <inheritdoc/>
    public class WopiSecurityHandler : IWopiSecurityHandler
    {
        private readonly ILogger _logger;
        private readonly JwtSecurityTokenHandler _tokenHandler = new();
        private SymmetricSecurityKey _key = null;
        private readonly IConfiguration _configuration;

        private SecurityKey Key
        {
            get
            {
                var client = new HttpClient();
                var disco = client.GetDiscoveryDocumentAsync($"{_configuration["AuthServer:Authority"]}").Result;

                var keys = new List<SecurityKey>();
                foreach (var webKey in disco.KeySet.Keys)
                {
                    var _key = new JsonWebKey()
                    {
                        Kty = webKey.Kty,
                        Alg = webKey.Alg,
                        Kid = webKey.Kid,
                        X = webKey.X,
                        Y = webKey.Y,
                        Crv = webKey.Crv,
                        E = webKey.E,
                        N = webKey.N,
                    };
                    keys.Add(_key);
                }

                //if (keys is null)
                //{
                //    //RandomNumberGenerator rng = RandomNumberGenerator.Create();
                //    //byte[] key = new byte[128];
                //    //rng.GetBytes(key);
                //    var key = Encoding.ASCII.GetBytes("secretKeysecretKeysecretKey123"/* + new Random(DateTime.Now.Millisecond).Next(1,999)*/);
                //    _key = new SymmetricSecurityKey(key);
                //}

                return keys[0];
            }
        }

        //TODO: abstract
        private readonly Dictionary<string, ClaimsPrincipal> _userDatabase = new()
        {
            {
                "Anonymous",
                new ClaimsPrincipal(
                new ClaimsIdentity(new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, "12345"),
                    new Claim(ClaimTypes.Name, "Anonymous"),
                    new Claim(ClaimTypes.Email, "anonymous@domain.tld"),

                    //TDOO: this needs to be done per file
                    new Claim(WopiClaimTypes.USER_PERMISSIONS, (WopiUserPermissions.UserCanWrite | WopiUserPermissions.UserCanRename | WopiUserPermissions.UserCanAttend | WopiUserPermissions.UserCanPresent).ToString())
                })
            )
            }
        };

        /// <summary>
        /// Creates a new instance of the <see cref="WopiSecurityHandler"/>.
        /// </summary>
        /// <param name="loggerFactory">An instance of a type used to configure the logging system and create instances of Microsoft.Extensions.Logging.ILogger from the registered Microsoft.Extensions.Logging.ILoggerProviders.</param>
        /// <param name="configuration">An instance of configuration</param>
        public WopiSecurityHandler(ILoggerFactory loggerFactory, IConfiguration configuration)
        {
            _logger = loggerFactory.CreateLogger<WopiSecurityHandler>();
            _configuration = configuration;
        }

        /// <inheritdoc/>
        public SecurityToken GenerateAccessToken(string userId, string resourceId)
        {
            var user = _userDatabase[userId];
            _key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Key.ToString()));
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = user.Identities.FirstOrDefault(),
                Expires = DateTime.UtcNow.AddHours(1), //access token ttl: https://wopi.readthedocs.io/projects/wopirest/en/latest/concepts.html#term-access-token-ttl
                SigningCredentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256Signature)
            };

            return _tokenHandler.CreateToken(tokenDescriptor);
        }

        /// <inheritdoc/>
        public ClaimsPrincipal GetPrincipal(string tokenString)
        {
            //TODO: https://github.com/aspnet/Security/tree/master/src/Microsoft.AspNetCore.Authentication.JwtBearer

            var tokenValidation = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateActor = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = Key,
                NameClaimType = "name",
                RoleClaimType = "role",

            };

            try
            {
                // Try to validate the token
                return _tokenHandler.ValidateToken(tokenString, tokenValidation, out var token);
            }
            catch (Exception ex)
            {
                _logger.LogError(new EventId(ex.HResult), ex, ex.Message);
                return null;
            }
        }

        /// <inheritdoc/>
        public bool IsAuthorized(ClaimsPrincipal principal, string resourceId, WopiAuthorizationRequirement operation)
        {
            //TODO: logic
            return principal.Identity.IsAuthenticated;
        }

        /// <summary>
        /// Converts the security token to a Base64 string.
        /// </summary>
        public string WriteToken(SecurityToken token)
        {
            return _tokenHandler.WriteToken(token);
        }
    }
}
