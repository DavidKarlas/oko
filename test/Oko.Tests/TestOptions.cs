using Microsoft.Extensions.Configuration;
using Oko;

namespace Oko.Tests;

/// <summary>
/// Builds <see cref="OkoOptions"/> the same way the host does — through the real environment-variable
/// parsing — so tests exercise configuration handling instead of bypassing it.
/// </summary>
internal static class TestOptions
{
    public static OkoOptions Create(string dataDirectory, params (string Key, string Value)[] overrides)
    {
        var settings = new Dictionary<string, string?>
        {
            ["DATA_DIR"] = dataDirectory,
            ["UDP_PORT"] = "37008",
            // The smallest legal values, so tests reach multi-block and multi-segment paths quickly.
            ["BLOCK_BYTES"] = OkoOptions.MinimumBlockBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["FLUSH_BYTES"] = "65536",
            ["FLUSH_INTERVAL"] = "00:00:01",
        };

        foreach ((string key, string value) in overrides)
        {
            settings[key] = value;
        }

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        return OkoOptions.FromConfiguration(configuration);
    }
}
