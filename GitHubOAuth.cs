using System;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Web;

namespace OAuthConsole
{
    static class GitHubOAuth
    {
        internal class Result
        {
            internal string Token;
            internal string Error;
        }

        internal static async Task<Result> GetToken(
            string clientId,
            string clientSecret,
            string state,
            string redirectUri,
            string htmlResponseToShowInBrowser)
        {
            // Creates an HttpListener to listen for requests on that redirect URI.
            var http = new HttpListener();
            http.Prefixes.Add(redirectUri);
            Debug("Listening on " + redirectUri);
            http.Start();

            // Creates the OAuth 2.0 authorization request.
            RequestIdentity.Request(clientId, state, redirectUri);

            // Waits for the OAuth authorization response.
            var context = await http.GetContextAsync();

            // Brings the Console to Focus.
            ConsoleHack.BringConsoleToFront();

            // Sends an HTTP response to the browser.
            var response = context.Response;

            var buffer = System.Text.Encoding.UTF8.GetBytes(htmlResponseToShowInBrowser);
            response.ContentLength64 = buffer.Length;
            var responseOutput = response.OutputStream;

            Task responseTask = responseOutput.WriteAsync(
                buffer, 0, buffer.Length).ContinueWith((task) =>
            {
                responseOutput.Close();
                http.Stop();
                Debug("HTTP server stopped.");
            });

            // Checks for errors.
            if (context.Request.QueryString.Get("error") != null)
            {
                return new Result()
                {
                    Token = null,
                    Error = string.Format("OAuth authorization error: {0}.",
                    context.Request.QueryString.Get("error"))
                };
            }

            if (context.Request.QueryString.Get("code") == null
                || context.Request.QueryString.Get("state") == null)
            {
                return new Result()
                {
                    Token = null,
                    Error = "Malformed authorization response. " + context.Request.QueryString
                };
            }

            // extracts the code
            var code = context.Request.QueryString.Get("code");
            var incoming_state = context.Request.QueryString.Get("state");

            // Compares the receieved state to the expected value, to ensure that
            // this app made the request which resulted in authorization.
            if (incoming_state != state)
            {
                return new Result()
                {
                    Token = null,
                    Error = string.Format(
                        "Received request with invalid state ({0})", incoming_state)
                };
            }

            Debug("Authorization code: " + code);
            return new Result()
            {
                Token = await RequestToken.Get(clientId, clientSecret, code, redirectUri, state),
                Error = null
            };
        }

        static class RequestIdentity
        {
            const string AuthorizationEndpoint = "http://github.com/login/oauth/authorize";

            internal static void Request(string clientId, string state, string redirectUri)
            {
                string authorizationRequest = string.Format(
                    "{0}?client_id={1}" +
                    "&redirect_uri={2}" +
                    "&scope=" +
                    "&state={3}" +
                    "&allow_signup=true",
                    AuthorizationEndpoint,
                    clientId,
                    System.Uri.EscapeDataString(redirectUri),
                    state);

                // Opens request in the browser.
                System.Diagnostics.Process.Start(authorizationRequest);
            }
        }

        static class RequestToken
        {
            const string TokenEndpoint = "https://github.com/login/oauth/access_token";

            static internal async Task<string> Get(
                string clientId,
                string clientSecret,
                string code,
                string redirectURI,
                string state)
            {
                Debug("Exchanging code for tokens...");

                // builds the  request
                string tokenRequestBody = string.Format(
                    "client_id={0}&client_secret={1}&code={2}&redirect_uri={3}&state={4}",
                    clientId,
                    clientSecret,
                    code,
                    System.Uri.EscapeDataString(redirectURI),
                    state);

                // sends the request
                HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(TokenEndpoint);
                tokenRequest.Method = "POST";
                tokenRequest.ContentType = "application/x-www-form-urlencoded";
                tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
                tokenRequest.ContentLength = _byteVersion.Length;
                Stream stream = tokenRequest.GetRequestStream();
                await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
                stream.Close();

                try
                {
                    // gets the response
                    WebResponse tokenResponse = await tokenRequest.GetResponseAsync();
                    using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
                    {
                        // reads response body
                        string responseText = await reader.ReadToEndAsync();
                        Console.WriteLine(responseText);

                        // By default, the response takes the following form:
                        // access_token=xxxxxxxxxxxxxxxxxx&token_type=bearer

                        string accessToken = HttpUtility.ParseQueryString(responseText)[0];

                        return accessToken;
                    }
                }
                catch (WebException ex)
                {
                    if (ex.Status == WebExceptionStatus.ProtocolError)
                    {
                        var response = ex.Response as HttpWebResponse;
                        if (response == null)
                            return string.Empty;

                        Debug("HTTP: " + response.StatusCode);

                        using (StreamReader reader = new StreamReader(
                            response.GetResponseStream()))
                        {
                            // reads response body
                            string responseText = reader.ReadToEnd();
                            Console.WriteLine(responseText);
                        }
                    }

                    return string.Empty;
                }
            }
        }

        static void Debug(string s)
        {
            Console.WriteLine(s);
        }
    }
}
