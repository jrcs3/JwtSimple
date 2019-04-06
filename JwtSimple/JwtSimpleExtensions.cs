using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace jrcs3.JwtSimple
{
    public static class JwtSimpleExtensions
    {
        /// <summary>
        /// A method to be run in Startup.ConfigureServices to setup JWT. 
        /// </summary>
        /// <param name="services">The Microsoft.Extensions.DependencyInjection.IServiceCollection to add services to</param>
        /// <param name="securityKey">A string that represents a Signing Key</param>
        /// <param name="issuer">A string that represents a valid issuer that will be used to check against the token's issuer.</param>
        /// <param name="audience">A string that represents a valid audience that will be used to check against the token's audience.</param>
        public static void SetupJwtSimple(this IServiceCollection services, string securityKey, string issuer, string audience)
        {
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = issuer,
                        ValidAudience = audience,
                        IssuerSigningKey = symmetricSecurityKey
                    };
                });
        }

        /// <summary>
        /// A method to create a JWT Token (JwtSecurityToken)
        /// </summary>
        /// <param name="securityKey">A string that represents a Signing Key</param>
        /// <param name="issuer">A string that represents a valid issuer that will be used to check against the token's issuer.</param>
        /// <param name="audience">A string that represents a valid audience that will be used to check against the token's audience.</param>
        /// <param name="claims">If this value is not null then for each System.Security.Claims.Claim a { 'Claim.Type',
        ///    'Claim.Value' } is added. If duplicate claims are found then a { 'Claim.Type',
        ///    List<object> } will be created to contain the duplicate values.</param>
        /// <returns>A new instance of the System.IdentityModel.Tokens.Jwt.JwtSecurityToken</returns>
        public static JwtSecurityToken CreateToken(string securityKey, string issuer, string audience, IEnumerable<Claim> claims)
        {
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256Signature);
            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: signingCredentials,
                claims: claims
                );
            return token;
        }

        /// <summary>
        /// Fetches the JWT from a HttpContext 
        /// </summary>
        /// <param name="context"></param>
        /// <param name="headerField"></param>
        /// <returns></returns>
        public static JwtSecurityToken getJwtFromContext(HttpContext context, string headerField = "Authorization")
        {
            string auth = context.Request.Headers[headerField];
            if (string.IsNullOrWhiteSpace(auth))
            {
                return null;
            }
            var authParts = auth.Split(' ');
            if (authParts.Length != 2)
            {
                return null;
            }
            try
            {
                return new JwtSecurityToken(authParts[1]);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Extracts a Claim by type key
        /// </summary>
        /// <param name="jwt"></param>
        /// <param name="typeKey"></param>
        /// <returns></returns>
        public static string getClaimByType(this JwtSecurityToken jwt, string typeKey)
        {
            foreach (var claim in jwt.Claims)
            {
                if (claim.Type == typeKey)
                {
                    return claim.Value;
                }
            }
            return string.Empty;
        }
    }
}
