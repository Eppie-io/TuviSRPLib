using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;
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
        ProtonSRPClient _client = new ProtonSRPClient();
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

                if(string.IsNullOrEmpty(_jsonFile))
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
            InitSRPClient(data);

            Encoding enc = Encoding.UTF8;
            byte[] passwordBytes = enc.GetBytes(_password);
            byte[] saltBytes = Base64.Decode(data.Salt);

            var decodedServerEphemeral = Base64.Decode(data.ServerEphemeral);
            BigInteger pubB = new BigInteger(1, decodedServerEphemeral.Reverse().ToArray());

            var ephemeral = _client.GenerateClientCredentials(saltBytes, passwordBytes);
            _client.CalculateSecret(pubB);
            var proof = _client.CalculateClientEvidenceMessage();


            var clientEphemeral = Base64.ToBase64String(ephemeral.ToLowEndianByteArray());
            var clientProof = Base64.ToBase64String(proof.ToLowEndianByteArray());

            return (clientEphemeral, clientProof);
        }

        void InitSRPClient(Response data)
        {
            BigInteger g = new BigInteger("2");
            IDigest digest = new ExtendedHashDigest();

            var decodedModulus = Base64.Decode(data.GetModulusData());
            BigInteger N = new BigInteger(1, decodedModulus.Reverse().ToArray());

            _client.Init(N, g, digest, new SecureRandom());
        }

        void WriteLine(string text, ConsoleColor color = ConsoleColor.White)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }
    }
}