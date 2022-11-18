#Chemin d'accès vers votre fichier d'importation CSV
$CSVFichier = ".\Employes.csv"
$ADUtilisateurs = Import-CSV -Path $CSVFichier -Delimiter ";" -Encoding UTF8

function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [ValidateRange(4,[int]::MaxValue)]
        [int] $length,
        [int] $upper = 1,
        [int] $lower = 1,
        [int] $numeric = 1,
        [int] $special = 1
    )

    $upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lowerCase = "abcdefghijklmnopqrstuvwxyz"
    $numberCase = "0123456789"
    $specialChar = "/*-+,!?=()@;:._"
    $defaultChar = ""
    if($upper -gt 0) { $defaultChar += $upperCase }
    if($lower -gt 0) { $defaultChar += $lowerCase }
    if($numeric -gt 0) { $defaultChar += $numberCase }
    if($special -gt 0) { $defaultChar += $specialChar }
    
    $defaultChar = $defaultChar.ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($length)
    $rng.GetBytes($bytes)
 
    $result = New-Object char[]($length)
    for ($i = 0 ; $i -lt $length ; $i++) {
        $result[$i] = $defaultChar[$bytes[$i] % $defaultChar.Length]
    }
    $password = (-join $result)
    $valid = $true
    if($upper   -gt ($password.ToCharArray() | Where-Object {$_ -cin $upperCase.ToCharArray() }).Count) { $valid = $false }
    if($lower   -gt ($password.ToCharArray() | Where-Object {$_ -cin $lowerCase.ToCharArray() }).Count) { $valid = $false }
    if($numeric -gt ($password.ToCharArray() | Where-Object {$_ -cin $numberCase.ToCharArray() }).Count) { $valid = $false }
    if($special -gt ($password.ToCharArray() | Where-Object {$_ -cin $specialChar.ToCharArray() }).Count) { $valid = $false }
 
    if(!$valid) {
         $password = Get-RandomPassword $length $upper $lower $numeric $special
    }
    return $password
}
Function Remove-StringSpecialCharacters
{

   Param([string]$String)

   $String -replace 'é', 'e' `
           -replace 'è', 'e' `
           -replace 'ç', 'c' `
           -replace 'ë', 'e' `
           -replace 'à', 'a' `
           -replace 'ö', 'o' `
           -replace 'ô', 'o' `
           -replace 'ü', 'u' `
           -replace 'ï', 'i' `
           -replace 'î', 'i' `
           -replace 'â', 'a' `
           -replace 'ê', 'e' `
           -replace 'û', 'u' `
           -replace '-', '' `
           -replace ' ', '' `
           -replace '/', '' `
           -replace '\*', '' `
           -replace "'", "" 
}
foreach ($User in $ADUtilisateurs)
{
 
       $Bureau      = Remove-StringSpecialCharacters $User.bureau.ToLower()
       $Prenom   = Remove-StringSpecialCharacters $User.prenom.ToLower()
       $Nom    = Remove-StringSpecialCharacters $User.nom.ToLower()
       $Departement  = Remove-StringSpecialCharacters $User.departement.ToLower()
       $MotDePasse = Get-RandomPassword 8
       $UserName = "$Prenom.$Nom"
       $Description = Remove-StringSpecialCharacters $User.description.ToLower()
       $NInterne = Remove-StringSpecialCharacters $User.n_interne.ToLower()
       
       if ($UserName.Length -gt 20) {
            $Prenom = $Prenom.substring(0, 1)
            $UserName = "$Prenom.$Nom"
            if ($UserName.Length -gt 20) {
                $Nom = $Nom.substring(0, 5)
                $UserName = "$Prenom.$Nom"
            }
       }

        #Ajout dans l'AD
            New-ADUser `
        -SamAccountName "$UserName" `
        -UserPrincipalName "$UserName@france.lan" `
        -Name "$Prenom $Nom" `
        -GivenName $Prenom `
        -Surname $Nom `
        -Enabled $True `
        -ChangePasswordAtLogon $True `
        -DisplayName "$Lastname, $Firstname" `
        -Department $Departement `
        -Path $OU `
        -AccountPassword (convertto-securestring $MotDePasse -AsPlainText -Force)

}