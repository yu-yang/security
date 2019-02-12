function e_d_file($key, $File){
        [byte[]] $key = $key;
        Write-Output $key
       
        $Suffix = "`.wannacookie";

        [System.Int32] $KeySize = $key.Length * 8;
        $AESP = New-Object 'System.Security.Cryptography.AesManaged';
        $AESP.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $AESP.BlockSize = 128;
        $AESP.KeySize = $KeySize;
        $AESP.Key = $key;
        $FileSR = New-Object System.IO.FileStream($File, [System.IO.FileMode]::Open);

        $DestFile = ($File -replace $Suffix)

        $FileSW = New-Object System.IO.FileStream($DestFile, [System.IO.FileMode]::Create);
       
        [Byte[]] $LenIV = New-Object Byte[] 4;
        $FileSR.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null;
        $FileSR.Read($LenIV, 0, 3) | Out-Null;
        [Int] $LIV = [System.BitConverter]::ToInt32($LenIV, 0);
        [Byte[]] $IV = New-Object Byte[] $LIV;
        $FileSR.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null;
        $FileSR.Read($IV,0, $LIV) | Out-Null;
        $AESP.IV = $IV;
        $Transform = $AESP.CreateDecryptor()

        $CryptoS = New-Object System.Security.Cryptography.CryptoStream($FileSW, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write);
        [Int] $Count = 0;
        [Int] $BlockSzBts = $AESP.BlockSize / 8;
        [Byte[]] $Data = New-Object Byte[] $BlockSzBts;
        Do {
            $Count = $FileSR.Read($Data, 0, $BlockSzBts);
            $CryptoS.Write($Data, 0, $Count)
        }
        While($Count -gt 0);
        $CryptoS.FlushFinalBlock();
        $CryptoS.Close();
        $FileSR.Close();
        $FileSW.Close();
};


function H2B {
    param($HX);
    $HX = $HX -split '(..)' | ?{  $_ };
    ForEach($value in $HX) {
        [Convert]::ToInt32($value, 16)
    }
};

$key = "fbcfc121915d99cc20a3d3d5d84f8308";
$file = 'C:\users\vagrant\alabaster_passwords.elfdb.wannacookie';

e_d_file $(H2B $key) $file;