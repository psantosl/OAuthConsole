using System;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Octokit;
using System.Collections.Generic;

namespace OAuthConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage: clientId clientSecret");
                return;
            }

            string clientId = args[0];
            string clientSecret = args[1];

            // Creates a redirect URI using an available port on the loopback address.
            string redirectURI = string.Format("http://{0}:{1}/signin-github/", "localhost", 5000);
            Console.WriteLine("redirect URI: " + redirectURI);

            string responseString = string.Format(
                @"<html>
                    <head>
                        <meta http-equiv='refresh' content='10;url=https://gmaster.io'>
                    </head>
                    <body>Please return to the app.</body>
                </html>");

            GitHubOAuth.Result result = GitHubOAuth.GetToken(
                clientId, clientSecret, State.Create(32), redirectURI, responseString).Result;

            var repos = ListGitHubRepos.Get(result.Token).Result;

            foreach (Repository rep in repos)
            {
                Console.WriteLine(rep.HtmlUrl);
            }

            Console.ReadKey();
        }

        static class ListGitHubRepos
        {
            internal static Task<IReadOnlyList<Repository>> Get(string token)
            {
                GitHubClient client = new GitHubClient(new ProductHeaderValue(
                    "test"));

                client.Credentials = new Credentials(token);

                return client.Repository.GetAllForCurrent();
            }
        }

        static class State
        {
            internal static string Create(uint length)
            {
                RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                byte[] bytes = new byte[length];
                rng.GetBytes(bytes);
                return base64urlencodeNoPadding(bytes);
            }

            static string base64urlencodeNoPadding(byte[] buffer)
            {
                string base64 = Convert.ToBase64String(buffer);

                // Converts base64 to base64url.
                base64 = base64.Replace("+", "-");
                base64 = base64.Replace("/", "_");
                // Strips padding.
                base64 = base64.Replace("=", "");

                return base64;
            }
        }
    }

    static class ConsoleHack
    {
        // Hack to bring the Console window to front.
        // ref: http://stackoverflow.com/a/12066376

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        internal static void BringConsoleToFront()
        {
            SetForegroundWindow(GetConsoleWindow());
        }
    }
}