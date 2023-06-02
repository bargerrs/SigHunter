function TestForSignatures {
    [CmdletBinding(DefaultParameterSetName='File')]
    param(
        [Parameter(Mandatory=$false, ParameterSetName='File', Position=0, HelpMessage='The path and name of the file to test for signatures.')]
        [string]$Filename = $null,

        [Parameter(Mandatory=$false, ParameterSetName='URL', Position=0, HelpMessage='The URL to download and test for signatures.')]
        [Uri]$URL,

        [Parameter(Mandatory=$false, ParameterSetName='ByteArray', Position=0, HelpMessage='The byte array to test for signatures.')]
        [byte[]]$ByteArray = $null,

        [Parameter(Mandatory=$false, HelpMessage='Specifies that the input data is base64-encoded.')]
        [switch]$Base64Encoded,

        [Parameter(Mandatory=$false, HelpMessage='Specifies the mode to use for testing the input data.')]
        [ValidateSet('File Deletion', 'Windows Defender')]
        [string]$TestMethod = 'File Deletion',

        [Parameter(Mandatory=$false, HelpMessage='Specifies the amount of time in seconds to wait for the file deletion test.')]
        [int]$WaitTime = 0
    )
    #=================================
    #=================================
    #=================================
    function Test-FileWithMethod {
        param (
            [byte[]]$ExeBytes,
            [string]$TestMethod,
            [int]$WaitTime = 90
        )

        $tempFile = [System.IO.Path]::GetTempFileName()
        # Write the byte array to the temporary file
        Set-Content -Path $tempFile -Value $ExeBytes -Encoding Byte
        $rVal = $false

        if ($TestMethod -eq 'File Deletion') {

            # Check if the file has been deleted every second for a maximum of $WaitTime seconds
            for ($i = 1; $i -le $WaitTime; $i++) {
                # Wait for 1 second
                Start-Sleep -Seconds 1

                # Check if the file still exists
                if (-not (Test-Path $tempFile)) {
                    # If the file doesn't exist, return true
                    $rVal = $true
                    break
                }
            }
        }
        elseif ($TestMethod -eq 'Windows Defender') {

            if (-not (Test-Path $tempFile)) {
                Write-Error "File not found."
                return
            }

            $scanResult = & $defenderExe -Scan -ScanType 3 -File $tempFile -DisableRemediation
            #IF "found no threats" is true; then this is inert.
            #Returns true if signatured.
            $result = -not ($scanResult -match "found no threats")
            $rVal = $result
        }

        # If the file still exists after the wait time, delete it and return false
        if (Test-Path $tempFile) {
            Remove-Item $tempFile
        }
        return $rVal
    }
    #=================================
    #=================================
    #=================================
    function BinarySearch {
        param (
            [int]$Start,
            [int]$End,
            [byte[]]$ByteArray,
            [string]$TestMethod,
            [int]$WaitTime = 90
        )


        if ([System.Math]::Abs($Start - $End) -gt 1) {
            $Mid = [int](($Start + $End) / 2)
            if (Test-FileWithMethod -ExeBytes $ByteArray[0..$Mid] -TestMethod $TestMethod -WaitTime $WaitTime) {
                #We just halved it.  And its still alerting.
                BinarySearch -Start $Start -End ($Mid -1) -ByteArray $ByteArray -TestMethod $TestMethod -WaitTime $WaitTime
            } else {
                BinarySearch -Start ($Mid + 1) -End $End -ByteArray $ByteArray -TestMethod $TestMethod -WaitTime $WaitTime
            }
        }else{
            $byteOffset = $End # specify the byte offset here
            if ([byte]$ByteArray[$End] -eq 0x00) {
                #Have to keep this from being 0x00 or it will break the findLast search later.
                $ByteArray[$End] = [char]0x46
            }
            # Read the contents of the file as a single string
            $encoding = [System.Text.Encoding]::ASCII
            $fileContent = $encoding.GetString($ByteArray)
            # Find the null character that precedes the word that contains the byte at the offset
            $nullIndex = $fileContent.LastIndexOf([char]0x00, $byteOffset)
            if(($End-$nullIndex -eq 0) -or ($nullIndex -eq -1)){
                $nullIndex = $fileContent.LastIndexOf([char]0x20, $byteOffset)
            }
            #Keep the returned value to less than 40 chars long
            $nullIndex = [Math]::Max($nullIndex, ($End - $maximumSigLength))
            #Set value max lenght (40 chars long) if less than 10 chars.
            if(($End-$nullIndex)-lt $minimumSigLength){
                $nullIndex = [Math]::Max(0, ($End - $maximumSigLength))
            }
            # Extract the word that contains the byte at the offset
            $wordStart = $nullIndex + 1
            $word = $fileContent.Substring($wordStart, $End - $wordStart)
            # Output the word and its location
            $hexString1 = '{0:X8}' -f $End
            $hexString2 = '{0:X8}' -f $wordStart
            Write-Host "Signature at byte $hexString1 : $word (starting at byte $hexString2)"

            #Modifying the in memory value of EXEBytes; to avoid detection next time.
            if ([byte]$ByteArray[$End] -eq 0x88) {
                $ByteArray[$End] = [char]0x85
            } else {
                $ByteArray[$End] = [char]0x88
            }

            if ([byte]$ByteArray[$Start] -eq 0x88) {
                $ByteArray[$Start] = [char]0x85
            } else {
                $ByteArray[$Start] = [char]0x88
            }

            return $ByteArray
        }
    }
    #=================================
    #=================================
    #=================================
    # Validate input sources
    $inputCount = @($Filename, $URL, $ByteArray) | Where-Object { $_ -ne $null -and $_ -ne "" } | Measure-Object | Select-Object -ExpandProperty Count
    if ($inputCount -ne 1) {
        throw "Please provide one input source: Filename, URL, or ByteArray."
    }


    # Warn if using File Deletion mode or methods that write to temp
    if ($TestMethod -eq 'File Deletion') {
        Write-Warning 'File Deletion mode is the slowest method. Consider using another mode for better performance.'
    }
    elseif ($TestMethod -eq 'Windows Defender') {
        Write-Warning 'Testing with Windows Defender will write files to the temp directory. Real-time detection should be disabled to continue.'

        # Prompt the user to continue or cancel
        $response = Read-Host 'Do you want to continue? (Y/N)'
        if ($response -ine 'Y') {
            return
        }
    }

    # Convert file or URL to bytearray if necessary
    switch ($PSCmdlet.ParameterSetName) {
        'File' {
            $Bytes = [System.IO.File]::ReadAllBytes($Filename)
        }
        'URL' {
            $WebClient = New-Object System.Net.WebClient
            $Bytes = $WebClient.DownloadData($URL)
        }
        'ByteArray' {
            $Bytes = $ByteArray
        }
    }

    # Convert base64-encoded data to bytearray if necessary
    if ($Base64Encoded) {
        $Bytes = [System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString($Bytes))
    }

    # Assign bytearray to $ByteArray variable
    $ByteArray = $Bytes
    $tempBytes = $ByteArray.Clone();
    $tempWaitTime =$WaitTime
    if($WaitTime -eq 0){
        #User didn't provide one
        $tempWaitTime = $defaultWaitTime
    }

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $firstRun = $true
    
    while (Test-FileWithMethod -ExeBytes $tempBytes -TestMethod $TestMethod -WaitTime $tempWaitTime) 
    {
        if($firstRun){
            $firstRun = $false
            $stopWatch.Stop()
            if($WaitTime -eq 0 -and $TestMethod -eq 'File Deletion'){
                #User didn't provide a wait time.
                #lets try to guess an efficient time. 150%
                $tempWaitTime = $stopWatch.Elapsed.TotalSeconds * $defaultWaitTimeIncrease
                Write-Warning "WaitTime parameter not provided. System is defaulting to $([int]$tempWaitTime) secs."
            }        
        }   
        
    
        $tempBytes = BinarySearch -Start 0 -End ($tempBytes.Length) -ByteArray $tempBytes -TestMethod $TestMethod -WaitTime $tempWaitTime
    }

}
###########################
# USER CONFIGUREABLE VALUES
###########################
#A filepath to MpCmdRun.exe is acceptable. The default value attempts to pull that filepath from the registry. 
$defenderExe = $(Join-Path (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender').InstallLocation 'MpCmdRun.exe')
#Default amount of time to wait during the first 'File Deletion' technique.
$defaultWaitTime = 90
#How much longer to we wait after this first successful 'File Deletion'?  Default is 50% longer.
$defaultWaitTimeIncrease = 1.5
#Maximum number of characters in a signature; for rendering output.
$maximumSigLength = 40
#Minimum number of characters in a signature; for rendering output.
$minimumSigLength = 10

###########################
# EXAMPLE USAGES
###########################
#Set-ExecutionPolicy Unrestricted -Scope CurrentUser

#TestForSignatures -Filename "C:\Example\testfile.exe" -TestMethod 'Windows Defender'
    #The above method will scan the exe with Windows Defender

#TestForSignatures -Filename "C:\Example\testfile.txt" -Base64Encoded -TestMethod 'Windows Defender'
    #The above example starts with test payload that has been base64encoded.
    #Once the base64'ed value decoded, it will be repeated scanned with Windows Defender 

#TestForSignatures -URL "https://example.com/testfile.txt" -Base64Encoded
    #The above example starts with a test payload that has been base64encoded and hosted on a remote website.  
    #The test method defaults to 'File Deletion'.  So in the above, the base64'ed value will be decoded and dropped to disc.
    #The script will check back continuously to see if it gets deleted.
    #Since no wait time was defined, the script will attempt to define an effficient wait time. 
    #Default initial wait time is 90 seconds.  The script will assume the file is NOT signatured if it survives over 90 seconds.
    #If the file is deleted before 90 seconds, the script will assign a wait time that is 50% longer for all future test.
    #If the first attempt got deleted 30 seconds, it will wait approx 45 seconds for all future deletion checks. 

#TestForSignatures -Filename "C:\Example\testfile.exe" -TestMethod 'File Deletion' -WaitTime 60
    #The above method will attempt to see it copying a file from one location to another (temp directory) will result in the new file being deleted.
    #File deletion indicates the file is signatured and was deleted by AV.
    #The script will assume any file that exists after 60 seconds is NOT signatured.
