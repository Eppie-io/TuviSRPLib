using System.Text.Json;
using TuviSRPLib;
using TuviSRPLib.Utils;

namespace Tuvi.Sample
{
    //  ProtonMail response json
    //  {
    //      "Code": 1000,
    //      "Modulus": "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nSample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sam\nSample+S\nSampl\n-----END PGP SIGNATURE-----\n",
    //      "ServerEphemeral": "Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample+Sample==",
    //      "Version": 4,
    //      "Salt": "Sample+Sample+==",
    //      "SRPSession": "fffffff0123456789abcdeffffffffff"
    //  }
    public record Response
    {
        public required string Modulus { get; init; }
        public required string ServerEphemeral { get; init; }
        public required string Salt { get; init; }

        public string GetModulusData()
        {
            var parts = Modulus.Split("\n");

            if (parts.Length > 4)
            {
                return parts[3];
            }

            return string.Empty;
        }

    }

    public class Program
    {
        string _password = string.Empty;
        string _jsonFile = string.Empty;
        Response? _data = null;

        public static void Main()
        {
            var app = new Program();
            app.Process();
        }

        void Process()
        {
            try
            {
                ParseArgs();

                if (string.IsNullOrEmpty(_jsonFile))
                {
                    throw new Exception("""json file is required [command line: -json "path"]""");
                }

                if (string.IsNullOrEmpty(_password))
                {
                    throw new Exception("""a password is required [command line: -psw "password"]""");
                }

                var json = GetJson(_jsonFile);
                WriteLine($"""
                    input:
                    {json}
                    """);

                ParseJson(json);

                var (clientEphemeral, clientProof) = Calculate(_data ?? throw new Exception("data is not found"));

                var result = Print(clientEphemeral, clientProof);

                WriteLine($"""

                    output:
                    {result}
                    """, ConsoleColor.Green);
            }
            catch (Exception ex)
            {
                WriteLine($"Error: {ex.Message}", ConsoleColor.Red);
            }
        }

        string Print(string clientEphemeral, string clientProof)
        {
            return $$"""
            {
                "clientEphemeral": "{{clientEphemeral}}",
                "clientProof": "{{clientProof}}"
            }
            """;
        }

        void ParseArgs()
        {
            var args = Environment.GetCommandLineArgs();

            for (var i = 0; i < args.Length - 1; ++i)
            {
                switch (args[i])
                {
                    case "-psw":
                        _password = args[++i];
                        break;
                    case "-json":
                        _jsonFile = args[++i];
                        break;
                }
            }
        }

        void ParseJson(string json)
        {
            _data = JsonSerializer.Deserialize<Response>(json);

            if (_data == null)
            {
                throw new Exception("Json can't be parsed");
            }
        }

        string GetJson(string file)
        {
            return File.ReadAllText(file);
        }

        (string clientEphemeral, string clientProof) Calculate(Response data)
        {
            ProtonSRPClient srpClient = new ProtonSRPClient();
            srpClient.SimpleInit(data.GetModulusData());

            var ephemeral = srpClient.GenerateClientCredentials(data.Salt, _password);
            srpClient.CalculateSecret(data.ServerEphemeral);

            var proof = srpClient.CalculateClientEvidenceMessage();

            return (ephemeral.ToBase64(), proof.ToBase64());
        }

        void WriteLine(string text, ConsoleColor color = ConsoleColor.White)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }
    }
}