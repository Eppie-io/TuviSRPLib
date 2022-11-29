using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;
using System.Text.Json;
using TuviSRPLib;

namespace Sample
{
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

    enum Command
    {
        create,
        calc,
        print,
        output,
        proof,
        exit,
        help,
    }

    public class Program
    {

        string jsonDefault = """
        {
            "Code": 1000,
            "Modulus": "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nS/hBgmVXHlpzUxgzOlt4veE3v3BnpaVyRFUUDMmRgcF2yZU5rQcQYHDBGrnQAlGdcsGmZVcZC51JgJtEB6v5bBpxnnsjg8XibZm0GYXODhm7qki5wM5AEKoTKbZKaKuRD297pPTsVdqUdXFNdkDxk3Q3nv3N6ZEJccCS1IabllN+/adVTjUfCMA9pyJavOOj90fhcCQ2npInsxegvlGvREr1JpobdrtbXAOzLH+9ELxpW91ZFWbN0HHaE8+JV8TsZnhY+W0pqL+x18iVBwOCKjqiNVlXsJsd4PV0fyX3Fb/uRTnUuEYe/98xo+qqG/CrhIW7QgiuwemEN7PdHHARnQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAADqcAEA3ZzmaFqnbwCxfGqupfOL\nv8s+Z2PoHQ5KjSkXzMW1RZEA/R1s3YA4h/mChLxEFYEgNHHaRqLh3fmLXY8q\nkd76+7UO\n=hVVV\n-----END PGP SIGNATURE-----\n",
            "ServerEphemeral": "wzpLV1YL4bNDW7nLT3BQRQf8jz94yVPf62wXXWj03l5nMePyOnvLddB2K0X8qnQa1F03i377iN6C+spT9AMMR7AWjnMTH3hyWeMPm8NQYteqHEc5eqgAyAEKI2C12Em1aOy506Ffw4IyUogRA5SA9vOdPyLd7ZGi05giWNqBwPsjECyKFjdAlVo1Akdk/svJA2XDb354S/2mTbpFa3ui4gooapQZcFTSMy7BPzeHtdYfq8n5UEc/rzJjOp2z+f2kdrdm3oDk7uXcc79b1GEUQFtK0HV2iMMGaOu61eQICay9TqqKRXpRQ+LZrCDBUkp2o+gunq2r7SyZfjraoZQaiw==",
            "Version": 4,
            "Salt": "tVWVRxVhW+8iMg==",
            "SRPSession": "d08b43395c925c08339afdb7cd060525"
        }
        """;

        ProtonSRPClient _client = new ProtonSRPClient();
        string _password = string.Empty;
        string _jsonFile = string.Empty;
        Response? data = null;

        string clientProof = string.Empty;
        string clientEphemeral = string.Empty;

        public static void Main()
        {
            try
            {
                var app = new Program();
                app.ParseJson(app.jsonDefault);

                app.Process();
            }
            catch (Exception ex)
            {
                var color = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Fatal Error: {ex.Message}");
                Console.ForegroundColor = color;
            }
        }

        void Process()
        {
            Help();

            var exit = false;
            while (!exit)
            {
                try
                {
                    Console.Write("command: ");
                    var cmd = Console.ReadLine();

                    switch (cmd)
                    {
                        case nameof(Command.create):
                            _client = new ProtonSRPClient();

                            ReadValue("Password: ", ReadPassword, ref _password);
                            ReadValue("Response json file: ", Console.ReadLine, ref _jsonFile);
                            ParseJson(GetJson(_jsonFile));
                            break;

                        case nameof(Command.calc):
                            (clientEphemeral, clientProof) = Calculate(data ?? throw new Exception("Response data is not found"));
                            break;

                        case nameof(Command.print):
                            Console.WriteLine(Print());
                            break;

                        case nameof(Command.output):

                            var output = "output.json";
                            ReadValue("Output file: ", Console.ReadLine, ref output);

                            File.WriteAllText(output, Print());
                            break;

                        case nameof(Command.proof):
                            break;

                        case nameof(Command.exit):
                            exit = true;
                            break;

                        case nameof(Command.help):
                            Help();
                            break;
                        default:
                            throw new Exception("Unknown command");
                    }
                }
                catch (Exception ex)
                {
                    var color = Console.ForegroundColor;
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"Warring: {ex.Message}");
                    Console.ForegroundColor = color;
                }

            }
        }

        void Help()
        {
            Console.WriteLine($"""
                List commands:
                    {nameof(Command.create)}
                    {nameof(Command.calc)}
                    {nameof(Command.print)}
                    {nameof(Command.output)}
                    {nameof(Command.proof)}
                    {nameof(Command.help)}
                    {nameof(Command.exit)}

                """);
        }

        string Print()
        {
            return $$"""
            {
                "clientEphemeral": "{{clientEphemeral}}",
                "clientProof": "{{clientProof}}"
            }
            """;
        }

        void ReadValue(string header, Func<string?> reader, ref string value)
        {
            if (!string.IsNullOrEmpty(header))
            {
                Console.Write(header);
            }

            var val = reader();

            if (!string.IsNullOrEmpty(val))
            {
                value = val;
            }
        }

        string? ReadPassword()
        {
            var pass = string.Empty;
            ConsoleKey key;

            var backspace = "\b \b";

            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write(backspace);
                    pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);
            Console.WriteLine();



            return pass;
        }

        void ParseJson(string json)
        {

            data = JsonSerializer.Deserialize<Response>(json);

            if (data == null)
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


    }
}