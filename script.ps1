﻿#Chemin d'accès vers votre fichier d'importation CSV
$CSVFichier = "C:\Users\Administrator\Desktop\Employes.csv"
$ADUtilisateurs = Import-CSV -Path $CSVFichier -Delimiter ";" -Encoding UTF8

#Clear du fichier texte qui contient les mdp
Clear-Content "C:\Users\Administrator\Desktop\mdp.txt"
#Créatoin de l'UO Paris

New-ADOrganizationalUnit -Name 'paris' -Path "DC=france,DC=lan"
New-ADOrganizationalUnit -Name 'groupes' -Path "OU=paris, DC=france,DC=lan"
New-ADOrganizationalUnit -Name 'GG' -Path "OU=groupes,OU=paris, DC=france,DC=lan"
New-ADOrganizationalUnit -Name 'GL' -Path "OU=groupes,OU=paris, DC=france,DC=lan"

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
    $MotDePasse = Get-RandomPassword 12
    $UserName = "$Prenom.$Nom"
    $Description = Remove-StringSpecialCharacters $Utilisateur.description.ToLower()
    $NInterne = Remove-StringSpecialCharacters $Utilisateur.n_interne.ToLower()
    $OU = "OU=$DepartementEnfant,OU=$DepartementParent,OU=paris,DC=france,DC=lan"

    if ($UserName.Length -gt 20) {
            $Prenom = $Prenom.substring(0, 1)
            $UserName = "$Prenom.$Nom"
            if ($UserName.Length -gt 20) {
                $Nom = $Nom.substring(0, 18)
                $UserName = "$Prenom.$Nom"
            }
    }
    if($DepartementParent -eq ""){
        $DepartementParent = $DepartementEnfant
        $OU = "OU=$DepartementParent,OU=paris,DC=france,DC=lan"
        if ($existingOU = Get-ADOrganizationalUnit -Filter "Name -like '$DepartementParent'"){
            Write-Warning "$DepartementParent existe."
        }
        else{
            New-ADOrganizationalUnit -Name $DepartementParent -Path "OU=paris,DC=france,DC=lan"
            New-ADGroup -Name "GG_$DepartementParent" -SamAccountName GG_$DepartementParent -GroupCategory Security -GroupScope Global -DisplayName "$DepartementParent" -Path "OU=GG,OU=groupes, OU=paris,DC=france,DC=lan" -Description "Membre du groupe global $DepartementParent"
            New-ADGroup -Name "GL_$DepartementParent._R" -SamAccountName GL_$DepartementParent.R -GroupCategory Security -GroupScope DomainLocal -DisplayName "GL_$DepartementParent.R" -Path "OU=GL,OU=groupes, OU=paris,DC=france,DC=lan" -Description "Membre du groupe local DepartementParent"
            New-ADGroup -Name "GL_$DepartementParent._RW" -SamAccountName GL_$DepartementParent.RW -GroupCategory Security -GroupScope DomainLocal -DisplayName "GL_$DepartementParent.RW" -Path "OU=GL,OU=groupes, OU=paris,DC=france,DC=lan" -Description "Membre du groupe local DepartementParent"
        }
    }

    if ($existingOU = Get-ADOrganizationalUnit -Filter "Name -like '$DepartementEnfant'"){
            Write-Warning "$DepartementParent existe."
    }
    else{
        if ($existingOU = Get-ADOrganizationalUnit -Filter "Name -like '$DepartementParent'"){
            Write-Warning "$DepartementParent existe."
            New-ADOrganizationalUnit -Name $DepartementEnfant -Path "OU=$DepartementParent,OU=paris,DC=france,DC=lan"
            New-ADGroup -Name "GL_$DepartementEnfant._R" -SamAccountName GL_$DepartementEnfant.R -GroupCategory Security -GroupScope DomainLocal -DisplayName "GL_$DepartementEnfant.R" -Path "OU=GL,OU=groupes, OU=paris,DC=france,DC=lan" -Description "Membre du groupe local $DepartementEnfant"
            New-ADGroup -Name "GL_$DepartementEnfant._RW" -SamAccountName GL_$DepartementEnfant.RW -GroupCategory Security -GroupScope DomainLocal -DisplayName "GL_$DepartementEnfant.RW" -Path "OU=GL,OU=groupes, OU=paris,DC=france,DC=lan" -Description "Membre du groupe local $DepartementEnfant"

        }
        else{
            New-ADOrganizationalUnit -Name $DepartementParent -Path "OU=paris,DC=france,DC=lan"
            New-ADGroup -Name "GG_$DepartementParent" -SamAccountName GG_$DepartementParent -GroupCategory Security -GroupScope Global -DisplayName "GG_$DepartementParent" -Path "OU=GG,OU=groupes, OU=paris,DC=france,DC=lan" -Description "Membre du groupe global $DepartementParent"
            New-ADOrganizationalUnit -Name $DepartementEnfant -Path "OU=$DepartementParent,OU=paris,DC=france,DC=lan"
            New-ADGroup -Name "GL_$DepartementEnfant._R" -SamAccountName GL_$DepartementEnfant.R -GroupCategory Security -GroupScope DomainLocal -DisplayName "GL_$DepartementEnfant.R" -Path "OU=GL,OU=groupes, OU=paris,DC=france,DC=lan" -Description "Membre du groupe local $DepartementEnfant"
            New-ADGroup -Name "GL_$DepartementEnfant._RW" -SamAccountName GL_$DepartementEnfant.RW -GroupCategory Security -GroupScope DomainLocal -DisplayName "GL_$DepartementEnfant.RW" -Path "OU=GL,OU=groupes, OU=paris,DC=france,DC=lan" -Description "Membre du groupe local $DepartementEnfant"

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
    -EmployeeNumber $NInterne `
    -ChangePasswordAtLogon $True `
    -DisplayName "$Nom, $Prenom" `
    -Department $Departement `
    -Path $OU `
    -AccountPassword (convertto-securestring $MotDePasse -AsPlainText -Force)

    Add-ADGroupMember -Identity "GG_$DepartementParent" -Members $UserName

    ADD-content -path "C:\Users\Administrator\Desktop\mdp.txt" -value "UserName : $UserName             Mot de passe : $MotDePasse"

}