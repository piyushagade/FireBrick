using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using FireBrick.Core.Models;

namespace FireBrick.Core.Engine;

/// <summary>
/// Verifies Windows Authenticode digital signatures using WinVerifyTrust and X509Certificate2.
/// Powers WFC's "Low Notification (unsigned only)" mode and UI publisher trust badges.
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly ConcurrentDictionary<string, SignatureInfoDto> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00000004;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, ref WINTRUST_DATA pWVTData);

    public static SignatureInfoDto Verify(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return new SignatureInfoDto
            {
                Status = SignatureTrustStatus.Unknown,
                Detail = "No executable path"
            };
        }

        if (filePath.Equals("System", StringComparison.OrdinalIgnoreCase))
        {
            return new SignatureInfoDto
            {
                Status = SignatureTrustStatus.Trusted,
                Publisher = "Microsoft Windows",
                Detail = "Windows Kernel / System"
            };
        }

        var expanded = Environment.ExpandEnvironmentVariables(filePath);
        if (Cache.TryGetValue(expanded, out var cached))
            return cached;

        var info = VerifyInternal(expanded);
        Cache[expanded] = info;
        return info;
    }

    public static void ClearCache() => Cache.Clear();

    private static SignatureInfoDto VerifyInternal(string filePath)
    {
        if (!File.Exists(filePath))
        {
            return new SignatureInfoDto
            {
                Status = SignatureTrustStatus.FileMissing,
                Detail = "File not found on disk"
            };
        }

        string publisher = string.Empty;
        string subject = string.Empty;
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
#pragma warning restore SYSLIB0057
            subject = cert.Subject;
            publisher = cert.GetNameInfo(X509NameType.SimpleName, false) ?? string.Empty;
        }
        catch
        {
            // No embedded signature (may still be catalog-signed for Windows inbox binaries)
        }

        var trustResult = CheckWinVerifyTrust(filePath);
        if (trustResult == 0)
        {
            return new SignatureInfoDto
            {
                Status = SignatureTrustStatus.Trusted,
                Publisher = string.IsNullOrWhiteSpace(publisher) ? "Verified Publisher" : publisher,
                Subject = subject,
                Detail = "Valid Authenticode signature"
            };
        }

        // TRUST_E_NOSIGNATURE = 0x800B0100 (-2146762496)
        if (trustResult == unchecked((int)0x800B0100))
        {
            return new SignatureInfoDto
            {
                Status = SignatureTrustStatus.Unsigned,
                Publisher = "Unsigned",
                Detail = "Executable is not digitally signed"
            };
        }

        return new SignatureInfoDto
        {
            Status = SignatureTrustStatus.Untrusted,
            Publisher = string.IsNullOrWhiteSpace(publisher) ? "Untrusted" : publisher,
            Subject = subject,
            Detail = $"Signature verification failed (0x{trustResult:X8})"
        };
    }

    private static int CheckWinVerifyTrust(string filePath)
    {
        IntPtr filePathPtr = IntPtr.Zero;
        IntPtr fileInfoPtr = IntPtr.Zero;
        try
        {
            filePathPtr = Marshal.StringToCoTaskMemUni(filePath);
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePathPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL
            };

            int result = WinVerifyTrust(IntPtr.Zero, WintrustActionGenericVerifyV2, ref data);

            // Close state handle
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, WintrustActionGenericVerifyV2, ref data);

            return result;
        }
        catch
        {
            return -1;
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(fileInfoPtr);
            if (filePathPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(filePathPtr);
        }
    }
}
