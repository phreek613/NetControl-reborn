# NetControl

Cross-platform network bandwidth diagnostics, device discovery, and ARP traffic management for local networks. Built with .NET 8 and Avalonia UI.

> [!IMPORTANT]
> Use NetControl only on networks you own or administer, and only with explicit authorization. ARP redirection and packet interception can disrupt devices and may be illegal without permission.

## Features

- Local network interface discovery
- ARP device discovery and identification
- Real-time per-device traffic monitoring
- ARP redirection and blocking controls
- Independent per-device download and upload limit controls
- Cross-platform Avalonia interface

## Supported Platforms

| Platform | Packet capture dependency |
| :--- | :--- |
| Windows x64 | Npcap |
| Linux x64 | libpcap |
| macOS x64 / arm64 | libpcap/BPF with root access |

## Windows Prerequisites

Install Npcap and enable WinPcap API-compatible mode during installation. Run NetControl with administrator privileges to open raw network adapters.

## Build

Prerequisites:

- .NET 8 SDK
- Platform network capture driver

```powershell
dotnet restore NetControl.sln
dotnet build NetControl.sln
dotnet test NetControl.sln
dotnet run --project NetControl/NetControl.csproj
```

## Publish for Windows

```powershell
dotnet publish NetControl/NetControl.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o dist/win-x64
```

## Security

- Do not run ARP controls on networks without authorization.
- Restore operations are attempted automatically when spoofing stops or the application closes.
- Raw packet capture and transmission require elevated privileges.

## License

MIT. See [LICENSE](LICENSE).
