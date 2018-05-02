
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.IO;
using System.Configuration;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace AzureJsonWebTokenValidator
{
    class Program
    {
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string audience = ConfigurationManager.AppSettings["ida:Audience"];
        private static string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);
        private static string metadataAddress = String.Format(CultureInfo.InvariantCulture, @"{0}/.well-known/openid-configuration", authority);
        private static string tokenFilePath = @"sample_token.txt";

        private static async Task<bool> validateJsonWebToken(string token)
        {
            try
            {
                IConfigurationManager<OpenIdConnectConfiguration> configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(metadataAddress, new OpenIdConnectConfigurationRetriever());
                OpenIdConnectConfiguration openIdConfig = await configurationManager.GetConfigurationAsync(CancellationToken.None);

                string issuer = openIdConfig.Issuer;
                TokenValidationParameters validationParameters = new TokenValidationParameters
                {
                    ValidIssuers = new[] { issuer, $"{issuer}/v2.0" },
                    ValidAudiences = new[] { audience },
                    IssuerSigningKeys = openIdConfig.SigningKeys
                };

                SecurityToken validatedToken;
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                var user = handler.ValidateToken(token, validationParameters, out validatedToken);

                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return false;
            }
        }

        static int Main(string[] args)
        {
            string token = File.ReadAllText(tokenFilePath);
            return validateJsonWebToken(token).Result ? 0 : 1;
        }
    }
}
