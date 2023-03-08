﻿# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$usage=$false;
$verbose=$true; #$false
$quiet=$false;
$whatif=$false;
[System.Collections.ArrayList]$userExcludeDirs=@();
[System.Collections.ArrayList]$userIncludeExts=@();
[System.Collections.ArrayList]$excludeDirs=@();
[System.Collections.ArrayList]$includeExts=@();
[System.Collections.ArrayList]$userFiles=@();


##==============================================================================
##
## Echo if verbose flag (ignores quiet flag)
##
##==============================================================================
function log_verbose()
{
    if ($verbose) {
        Write-Host "$args"
    }
}

##==============================================================================
##
## Echo if whatif flag is specified but not quiet flag
##
##==============================================================================
function log_whatif()
{
    if ( $whatif  -and -not $quiet)
    {
        Write-Host "$args"
    }
}

##==============================================================================
##
## Process command-line options:
##
##==============================================================================

foreach ($opt in $args)
{
  switch -regex ($opt) {

    "-h" {}
    "--help" {
            $usage=$true; break;
        }

    "-v" {
             # FALLTHROUGH
         }
   "--verbose" {
           $verbose=$true; break;
        }

    "-q" {
             # FALLTHROUGH
        }
    "--quiet" {
            $quiet=$true; break;
        }

    "-w" {
            #FALLTHROUGH
         }
    "--whatif" {
            $whatif=$true; break;
        }

    "--exclude-dirs=*" {
            $userExcludeDirs=($opt -split "=")[1];
            break;
        }

    "--include-exts=*" {
           $userIncludeExts=($opt -split "=")[1];
           break;
        }

    "--files=*" {
            $userFiless=($opt -split "=")[1];
           break;
        }
    default {
           Write-Error "$PSCommandPath unknown option:  $opt"
           exit 1
           break;
        }
    }
}

##==============================================================================
##
## Display help
##
##==============================================================================

if ( $usage ) {
    $usageMessage = @'

OVERVIEW:

Formats all C/C++ source files based on the .clang-format rules

    $ format-code [-h] [-v] [-w] [--exclude-dirs="..."] [--include-exts="..."] [--files="..."]

OPTIONS:
    -h, --help              Print this help message.
    -v, --verbose           Display verbose output.
    -v, --quiet             Display only clang-format output and errors.
    -w, --whatif            Run the script without actually modifying the files
                            and display the diff of expected changes, if any.
    --exclude-dirs          Subdirectories to exclude. If unspecified, then
                            ./3rdparty, ./build and ./prereqs are excluded.
                            All subdirectories are relative to the current path.
    --include-exts          File extensions to include for formatting. If
                            unspecified, then *.h, *.c and *.cpp are included.
    --files                 Only run the script against the specified files from
                            the current directory.

EXAMPLES:

To determine what lines of each file in the default configuration would be
modified by format-code, you can run from the root folder:

    $ ./scripts/format-code -w

To update only all .c and .cpp files in tests/ except for tests/echo/host, you
can run from the tests folder:

    tests$ ../scripts/format-code --exclude-dirs="echo/host" \
      --include-exts="c cpp"

To run only against a specified set of comma separated files in the current directory:

    $ ./scripts/format-code -w --files="file1 file2"

'@
    Write-Host "$usageMessage"
    exit 0
}

##==============================================================================
##
## Determine parameters for finding files to format
##
##==============================================================================
function get_find_args()
{
    $defaultExcludeDirs=@( ".git", "3rdparty", "prereqs", "build", "*.cquery_cached_index" );
    $defaultIncludeExts=@( "h", "c", "cpp" )

    $findargs='get-childitem -Recurse -Name "*" -Path "." '
    if ( !($userIncludeExts) ) {
        # not local as this is used in get_file_list() too
        $includeExts.AddRange($defaultIncludeExts)
    }
    else
    {
        log_verbose "Using user extension inclusions: $userIncludeExts"
        $includeExts.AddRange($userIncludeExts)
    }

    $findargs+=" -Include @( "
    foreach ($ext in $includeExts)
    {
        $findargs+=("'*."+"$ext'")
        if ($includeExts.IndexOf($ext) -lt $includeExts.count-1)
        {
            $findargs+=", "
        }
    }
    $findargs+=") "

    if (  !($userExcludeDirs) ) {
        $excludeDirs.AddRange($defaultExcludeDirs)
    }
    else {
        log_verbose "Using user directory exclusions: $userExcludeDirs"
        $excludeDirs.AddRange($userExcludeDirs)
    }

    $findargs+=" | where { "
    foreach ($dir in $excludeDirs)
    {
        $findargs+='$_ -notlike '
        $findargs+= "'$dir"+"\*'"
        if ($excludeDirs.IndexOf($dir) -lt $excludeDirs.count-1)
        {
            $findargs+=" -and  "
        }
    }
    $findargs+="} "

    return $findargs
}

function get_file_list()
{
    if ( !($userFiles) ) {
        $findargs = get_find_args;
        $file_list = Invoke-Expression($findargs)
        if ( $file_list.count -eq 0 ) {
           Write-Host "No files were found to format!"
           exit 1
        }
    }
    else {
       log_verbose "Using user files: $userfiles"
       $user_file_list = @()
       foreach ( $uf in $userfiles )
       {
           $user_file_list+= get-ChildItem -Path '.' -Name $uf
       }
       $file_list=@()
       foreach ( $file in $user_file_list ) {

            foreach ( $ext in $includeExts ) {
                if ( $file.Extension -match "$ext" ) {
                    file_list+=$file
                    log_verbose "Checking user file: $file"
                    break;
                }
            }
        }
    }
    return $file_list
}

$global:cf=""

##==============================================================================
##
## Check for installed clang-format tool
##
##==============================================================================
function check_clang-format()
{
    # Windows does not have a clang-format-7 executable


    $required_cfver='7.0.0'

    try {
       $cfver=(( Invoke-Expression "clang-format --version" 2> $null ) -split " ")[2]
    }
    catch {
        Write-Host "clang-format not installed"
        return $false
    }

    $req_ver = $required_cfver -split '.'
    $cf_ver  = $cfver -split '.'

    for ($i = 0; $i -lt 3; $i++)
    {
        if ( $cf_ver[$i] -gt $req_ver[$i])
        {
            return $true
        }

        if ( $cf_ver[$i] -lt $req_ver[$i])
        {
            Write_host "Required version of clang format is $reqired_cfver. Current version is $cfver"
            return $false
        }
        # Equal just keeps going
    }
    $global:cf="clang-format"
    return $true
}


##==============================================================================
##
## Mainline: Call clang-format for each file to be formatted
##
##==============================================================================

if (!(check_clang-format)) # getting the filelist takes a few seconds. If we cant format we may as well exit now.
{
    exit -1
}

$filelist = get_file_list;
$filecount=0
$changecount=0

$cfargs="$global:cf -style=file"
if ( !$whatif ) {
    $cfargs="$cfargs -i"
}

foreach ( $file in $filelist ) {
    $filecount+=1;
    $cf="$cfargs $file"


    if ( $whatif ) {
        log_whatif "Formatting $file ..."
        ( Invoke-Expression ($cf) ) | Compare-Object (get-content $file)
    }
    else {
        if ( $verbose ) {
            log_verbose "Formatting $file ..."
            Invoke-Expression $cf
        }
        else {
            Invoke-Expression $cf > $null
        }
    }
    if ( $? ) {
        if ( $whatif ) {
            $changecount++
        }
    }
    else {
        Write-Host "clang-format failed on file: $file."
    }
}

log_whatif "$filecount files processed, $changecount changed."

# If files are being edited, this count is zero so we exit with success.
exit $changecount
