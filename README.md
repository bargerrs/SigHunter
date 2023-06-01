# Script Name
SIG HUNTER

## Description
A PowerShell script designed to identify signatured sections in a file that may trigger AD/EDR systems. It utilizes binary tree search methodology to hunt through the file for signatures. The script offers two detection techniques: Windows Defender scanning and File Deletion analysis.

### Windows Defender Technique
This technique scans the file using Windows Defender to identify signatured sections.

### File Deletion Technique
This technique drops the file into the temporary directory and monitors if it gets deleted. If the file is deleted within a specified time frame, it indicates that the file is signatured.

## Usage
The `TestForSignatures` function is the main function to interact with. It has several parameters to customize the testing process:

```powershell
TestForSignatures -Filename <FilePath> -TestMethod <DetectionMethod> [-Base64Encoded] [-WaitTime <Seconds>]
```

### Parameters
- `Filename` (Optional): The path and name of the file to test for signatures.
- `URL` (Optional): The URL to download and test for signatures.
- `ByteArray` (Optional): The byte array to test for signatures.
- `Base64Encoded` (Switch): Specifies that the input data is base64-encoded.
- `TestMethod` (Required): Specifies the detection method to use. Choose between 'File Deletion' or 'Windows Defender'.
- `WaitTime` (Optional): Specifies the amount of time in seconds to wait for the file deletion test.

## User Configurable Values

Before running the script, you can opt to modify the following variables according to your environment:

- `$defenderExe`: The file path to the `MpCmdRun.exe` executable for Windows Defender scanning. The default value attempts to retrieve it from the registry.
- `$defaultWaitTime`: The default amount of time in seconds to wait during the first 'File Deletion' technique.
- `$defaultWaitTimeIncrease`: The multiplier to increase the wait time after the first successful 'File Deletion'.

## Example Usages

Here are a few examples demonstrating how to use the script:

1. Scan an executable file with Windows Defender:

```powershell
TestForSignatures -Filename "C:\Example\testFile.exe" -TestMethod 'Windows Defender'
```

2. Scan a text file that is base64-encoded with Windows Defender:

```powershell
TestForSignatures -Filename "C:\Example\testfile.txt" -Base64Encoded -TestMethod 'Windows Defender'
```

3. Download a base64-encoded payload from a remote URL and perform the 'File Deletion' test:

```powershell
TestForSignatures -URL "https://example.com/testfile.txt" -Base64Encoded
```

4. Perform the 'File Deletion' test on a specific file with a wait time of 60 seconds:

```powershell
TestForSignatures -Filename "C:\Example\testfile.exe" -TestMethod 'File Deletion' -WaitTime 60
```
