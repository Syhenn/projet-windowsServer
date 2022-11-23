#Chemin d'accès vers votre fichier d'importation CSV
$CSVFichier = "C:\Users\Administrator\Desktop\Employes.csv"
$ADUtilisateurs = Import-CSV -Path $CSVFichier -Delimiter ";" -Encoding UTF8

#Récupération des informations du domaine
$domainSplit = $env:USERDNSDOMAIN.ToLower().split('.')
$domain = $domainSplit[0]
$domainExt = $domainSplit[1]



#Clear du fichier texte qui contient les mdp
Clear-Content "C:\Users\Administrator\Desktop\mdp.txt"

New-ADOrganizationalUnit -Name 'groupes' -Path "DC=$domain,DC=$domainExt"
New-ADOrganizationalUnit -Name 'GG' -Path "OU=groupes, DC=$domain,DC=$domainExt"
New-ADOrganizationalUnit -Name 'GL' -Path "OU=groupes, DC=$domain,DC=$domainExt"

#Génération mot de passe aléatoire
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
    $specialChar = "/*-!@"
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

#securite de caractère pour l'ADDS
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
           -replace 'À','a' `
           -replace 'Â','a' `
           -replace 'Ä','a' `
           -replace 'Ê','e' `
           -replace 'Ë','e' `
           -replace 'Æ','ae' `
           -replace 'É','e' `
           -replace 'È','e' `
           -replace 'Î','i' `
           -replace 'Ï','i' `
           -replace 'Ô','o' `
           -replace 'Ö','o' `
           -replace 'Û','u' `
           -replace 'Ü','u' `
           -replace 'æ','ae' `
           -replace 'Œ','oe' `
           -replace 'œ','oe' `
           -replace 'Ù','u' `
           -replace '-', '' `
           -replace ' ', '' `
           -replace '/', '' `
           -replace '\*', '' `
           -replace "'", "" 
}

#Fonction qui vérifie si une UO existe ou pas
function checkIfOuExists{

param(

    [parameter(Mandatory)]

    [string]$nameOfOU

)

$existingOU = Get-ADOrganizationalUnit -Filter 'Name -like "$nameOfOU"'

if($existingOU -eq $null){
    return $false
}
else{
    return $true
}

}

foreach ($Utilisateur in $ADUtilisateurs)
{
    $Bureau      = Remove-StringSpecialCharacters $Utilisateur.bureau.ToLower()
    $Prenom   = Remove-StringSpecialCharacters $Utilisateur.prenom.ToLower()
    $Nom    = Remove-StringSpecialCharacters $Utilisateur.nom.ToLower()
    $Departement  = $Utilisateur.departement.ToLower()
    $DepartementSplit = $Departement.split('/')
    $DepartementParent = Remove-StringSpecialCharacters $DepartementSplit[1]
    $DepartementEnfant = Remove-StringSpecialCharacters $DepartementSplit[0]
    $MotDePasse = Get-RandomPassword 7
    $UserName = "$Prenom.$Nom"
    $Description = Remove-StringSpecialCharacters $Utilisateur.description.ToLower()
    $NInterne = Remove-StringSpecialCharacters $Utilisateur.n_interne.ToLower()
    $OU = "OU=$DepartementEnfant,OU=$DepartementParent,DC=$domain,DC=$domainExt"

    if ($UserName.Length -gt 20) {
            $Prenom_coupe = $Prenom.substring(0, 1)
            $UserName = "$Prenom_coupe.$Nom"
            if ($UserName.Length -gt 20) {
                $Nom_coupe = $Nom.substring(0, 18)
                $UserName = "$Prenom_coupe.$Nom_coupe"
            }
    }
    if($DepartementParent -eq ""){
        $DepartementParent = $DepartementEnfant
        $OU = "OU=$DepartementParent,DC=$domain,DC=$domainExt"
        if ($existingOU = Get-ADOrganizationalUnit -Filter "Name -like '$DepartementParent'"){
            Write-Warning "$DepartementParent existe."
        }
        else{
            New-ADOrganizationalUnit -Name $DepartementParent -Path "DC=$domain,DC=$domainExt"
            New-ADGroup -Name "GG_$DepartementParent" -SamAccountName GG_$DepartementParent -GroupCategory Security -GroupScope Global -DisplayName "$DepartementParent" -Path "OU=GG,OU=groupes,DC=$domain,DC=$domainExt" -Description "Membre du groupe global $DepartementParent"
            New-ADGroup -Name GL_${DepartementParent}_R -SamAccountName GL_${DepartementParent}_R -GroupCategory Security -GroupScope DomainLocal -DisplayName GL_${DepartementParent}_R -Path "OU=GL,OU=groupes,DC=$domain,DC=$domainExt" -Description "Membre du groupe local $DepartementParent"
            New-ADGroup -Name GL_${DepartementParent}_RW -SamAccountName GL_${DepartementParent}_RW -GroupCategory Security -GroupScope DomainLocal -DisplayName GL_${DepartementParent}_RW -Path "OU=GL,OU=groupes,DC=$domain,DC=$domainExt" -Description "Membre du groupe local $DepartementParent"
        }
    }

    if ($existingOU = Get-ADOrganizationalUnit -Filter "Name -like '$DepartementEnfant'"){
            Write-Warning "$DepartementParent existe."
    }
    else{
        New-ADGroup -Name "GG_$DepartementEnfant" -SamAccountName GG_$DepartementEnfant -GroupCategory Security -GroupScope Global -DisplayName "$DepartementEnfant" -Path "OU=GG,OU=groupes,DC=$domain,DC=$domainExt" -Description "Membre du groupe global $DepartementParent"
        New-ADGroup -Name GL_${DepartementEnfant}_R -SamAccountName GL_${DepartementEnfant}_R -GroupCategory Security -GroupScope DomainLocal -DisplayName GL_${DepartementEnfant}_R -Path "OU=GL,OU=groupes,DC=$domain,DC=$domainExt" -Description "Membre du groupe local $DepartementEnfant"
        New-ADGroup -Name GL_${DepartementEnfant}_RW -SamAccountName GL_${DepartementEnfant}_RW -GroupCategory Security -GroupScope DomainLocal -DisplayName GL_${DepartementEnfant}_RW -Path "OU=GL,OU=groupes,DC=$domain,DC=$domainExt" -Description "Membre du groupe local $DepartementEnfant"

        if ($existingOU = Get-ADOrganizationalUnit -Filter "Name -like '$DepartementParent'"){
            Write-Warning "$DepartementParent existe."
            New-ADOrganizationalUnit -Name $DepartementEnfant -Path "OU=$DepartementParent,DC=$domain,DC=$domainExt"


        }
        else{
            New-ADOrganizationalUnit -Name $DepartementParent -Path "DC=$domain,DC=$domainExt"
            New-ADGroup -Name "GG_$DepartementParent" -SamAccountName GG_$DepartementParent -GroupCategory Security -GroupScope Global -DisplayName "GG_$DepartementParent" -Path "OU=GG,OU=groupes,DC=$domain,DC=$domainExt" -Description "Membre du groupe global $DepartementParent"
            New-ADOrganizationalUnit -Name $DepartementEnfant -Path "OU=$DepartementParent,DC=$domain,DC=$domainExt"
        }
        Add-ADGroupMember -Identity "GG_$DepartementParent" -Members GG_$DepartementEnfant
    }
        
    #Ajout dans l'AD
    New-ADUser `
    -SamAccountName "$UserName" `
    -UserPrincipalName "$UserName@$domain.$domainExt" `
    -Name "$Prenom $Nom" `
    -GivenName $Prenom `
    -Surname $Nom `
    -Enabled $True `
    -EmployeeNumber $NInterne `
    -ChangePasswordAtLogon $True `
    -DisplayName "$Nom, $Prenom" `
    -Department $DepartementEnfant `
    -Path $OU `
    -Office $Bureau `
    -AccountPassword (convertto-securestring $MotDePasse -AsPlainText -Force)

    Set-ADUser -Identity $UserName -Replace @{ ipPhone = $NInterne }
    Add-ADGroupMember -Identity "GG_$DepartementEnfant" -Members $UserName

    ADD-content -path "C:\Users\Administrator\Desktop\mdp.txt" -value "UserName : $UserName             Mot de passe : $MotDePasse"

}