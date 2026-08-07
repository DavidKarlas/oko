using System.Reflection;

namespace Oko;

internal static class OkoVersion
{
    // Declaration order matters: static initialisers run top to bottom, so Version must be assigned
    // before UserApplication reads it. With these reversed, every capture file recorded "Oko/".
    public static string Version { get; } =
        typeof(OkoVersion).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion.Split('+')[0]
        ?? "0.0.0";

    /// <summary>Recorded in every capture's <c>shb_userappl</c>, so a file identifies what wrote it.</summary>
    public static string UserApplication { get; } = $"Oko/{Version}";
}
