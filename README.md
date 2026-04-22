# CDP-Enable-BOF

`CDP-Enable-BOF` is an x64 BOF that enables the Chrome DevTools Protocol in a
running `msedge.exe` or `chrome.exe` process 

Based on [CDP-Enable](https://github.com/deathflamingo/CDP-Enabler/) and [Modern Session Hijacking by Living off the DevTools Protocol by Cedric Van Bockhaven](https://specterops.io/so-con/)

## Usage

```text
cdp_enable <edge|chrome> <9000-65535>
```

## How It Works

- finds the requested live browser process and its top-level window
- locates the loaded browser module (`msedge.dll` or `chrome.dll`)
- reads the module’s PE headers and sections from the remote process
- resolves these internal symbols at runtime using masked byte signatures:
  - `StartRemoteDebuggingServer`
  - `operator new`
  - `TCPServerSocketFactory::CreateForHttpServer`
  - `TCPServerSocketFactory` vtable
- allocates two small remote stubs plus a context block
- temporarily installs a remote window procedure
- triggers that window procedure on the browser UI thread
- calls `StartRemoteDebuggingServer` on the requested port

Running the final internal call on the browser UI thread is the key trick that
makes this reliable in the presence of CFG / TLS / CET-sensitive execution.


## Validate

Use the bundled Python script to prove CDP is up and reachable:

```powershell
python .\grab_cookies.py --port 9001 --output cookies.json
```

If CDP is working, the script will:

- resolve the browser websocket from `http://127.0.0.1:9001/json/version`
- connect to the websocket
- dump cookies to `cookies.json`

Optional domain filter:

```powershell
python .\grab_cookies.py --port 9001 --domain microsoft.com --output ms_cookies.json
```

## Common Issue

Issue: "Failed to resolve symbol signatures"

Cause: Edge version mismatch - signatures are version-specific
Solution: See "Finding New Signatures" below

Tested Chrome Version: 147.0.7727.102
Tested Edge Version: 147.0.3912.72

## Finding New Signatures

The finder scripts are still included because they are useful for:

- validating new signatures
- checking symbol drift across browser versions
- reverse engineering / troubleshooting

### Pull the DLLs

Typical browser DLL locations:

```powershell
Copy-Item "$env:ProgramFiles\\Google\\Chrome\\Application\\chrome.dll" .
Copy-Item "${env:ProgramFiles(x86)}\\Microsoft\\Edge\\Application\\msedge.dll" .
```

### Pull the matching PDBs

For Chrome:

```powershell
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com
```

For Edge:

```powershell
symchk /v /ocx edge-symchk.txt /s SRV*c:\symbols*https://msdl.microsoft.com/download/symbols .\msedge.dll
```

### Run the scripts

Find `StartRemoteDebuggingServer`:

```powershell
python .\find_start_server.py .\chrome.dll .\chrome.dll.pdb
python .\find_start_server.py .\msedge.dll .\msedge.dll.pdb
```

Find the supporting inputs:

```powershell
python .\find_cdp_inputs.py .\chrome.dll .\chrome.dll.pdb
python .\find_cdp_inputs.py .\msedge.dll .\msedge.dll.pdb
```

These scripts emit:

- `StartRemoteDebuggingServer`
- `operator new`
- `TCPServerSocketFactory::CreateForHttpServer`
- derived `TCPServerSocketFactory` vtable

## Notes

- x64 only
- tested with both `msedge.exe` and `chrome.exe`
- the BOF only targets the browser you explicitly pass as an argument
- the current Chrome resolver uses a stronger masked `CreateForHttpServer`
  signature to avoid false positives across patch-level browser changes


