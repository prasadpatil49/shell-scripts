#!/usr/bin/ksh

#===============================================================================
# Version Date         # Author             Description
#===============================================================================
# V1.1  2007-08-02   # iwong  Updated code to read URT format CCC/I/SSSSSS//gecos
# V1.2  2007-11-29   # iwong  Updated code read in cust and comment fomr URT format CCC/I/SSSSSS/cust/comment
# V2.0  2007-11-30   # iwong  Updated code output .scm9 format, which includes auditDATE
#              #        Updated code to indicate if SUDO priv is granted by a group(SUDO-GRP) or user(SUDO-USR)
#        #        Updated warning messages to indicated which files are missing
#                    #        Updated code to read CIO format S=SSSSSSCCC
# V2.1  2007-12-04   # iwong  Updated code to check for HP-UX systems(TCB and non-TCB)
#        #        Updated code to warn if no sudoers files found
# V2.2  2007-12-05   # iwong  Updated code to check for HP-UX systems for /usr/bin/false
# V2.3  2007-12-11   # iwong  If comments contain IBM flag = I
# V2.4  2008-02-21   # iwong  Updated code output .mef format
# V2.5  2008-03-04   # iwong  Updated code changing SUDO-USR to SUDO and SUDO-GRP to list of sudo groups
# V2.6  2008-03-05   # iwong  Bypass disabled check for * in passwd field in passwd file on hpux TCB systems
#                             Moved shell false check out of get_state into passwd loop
#                             Created new hpux_get_state subroutine to check getprpw or shadow file
#                             Added -d flag to enable debugging messages
# V3.0  2008-04-17   # iwong  Added -S flag, to output scm9 format
#           Output OS type in scm formated files
#           Recognize OSR privileged user and groups per OS type
#           Updated groups and privileges fields include OSR ans SUDO privs
#           Remove 3-digit CC conversion
#           Added -P flag to read in additional priv groups from a file
#           Updated code output .mef3 format
#           Add primary group processing priv group/sudo groups
# V3.1  2008-04-24   # iwong  Updated code group field output to list all groups a user is a member
#                 Add wheel to Linux default priv group list
#                 Fixed sed S= parsing, which didnt work on AIX or Linux
# V3.2  2008-04-30   # iwong  Added code to skip Defaults in sudoers file
#           Added code to fix problem with lines with trailing and leading spaces/tabs in sudoers file
#           Added additional debug statements for sudoers processing
#           Increased AssocArr element limit from 255 to 99999
#           Added addtional processing of ALL keyword in sudoers
# V3.3  2008-05-01   # iwong  Removed description matching for URT/CIO/IBM formats
# V3.4   2008-05-07   # iwong  Updated sed command for removing trailing/leading spaces using [:space:]
# V3.4.1 2008-05-13   # iwong  Updated sed command fixing problem with joining lines in AIX
# V3.5   2008-05-15   # iwong  Added -M flag, to output mef2 format
# V3.6   2008-05-15   # iwong  Changed directory to /tmp for default output file
#                     # iwong  Fixed probelm with extra newline in scm formated files
# V3.7   2008-06-03   # iwong  Added code to process groups in the User_Alias
# V3.8   2008-06-11   # iwong  Added code ignore netgroup ids +@user, any id starting with +
# V3.9   2008-07-07   # iwong  Added code adding dummy record to end of output file with date and versioning information
# V3.10  2008-07-28   # iwong  Updated dummy record to include 000 cc
# V4.0   2008-10-02   # iwong  Added code to process/recognize Host_Aliases in sudoers file
#                              Added code to process/recognize User_Aliases only if they are used 
#                              Added code to list Linux groups with gid < 99 as privileged
# V4.1   2009-01-08   # iwong  Added code to get sudo version
#                              Updated signature record to include FN= amd SUDO=
# V4.2   2009-03-24   # M Ram  Added code to Ignore SUDOALL if "ALL=!SUDUSUDO" rule found
#            Added code to ignore netgroup ids while parsing Sudoers
#            Updated code to remove spaces in Date
#            Updated code to keep tmpfile in /tmp
# V4.3   2009-04-10    # M Ram  Added code to print custom signature for dummy id
# V4.4   2009-04-15    # M Ram  Added code to check SSH public key authentation status for users having password "*" in passwd file
# V4.5   2009-08-25    # M Ram  Added code to fetch IDs from NIS service
#      2009-10-01    # M Ram  Added code to process Netuser and Netgroup IDs ( start with + )
#                # M Ram  Added code to display user last login date for AIX servers
#                  # M Ram  Fixed the problem with disabled id has password like *LK*{crypt} in solaris
#                # M Ram  Updated code to process PRIV file in linux environment
#                # M Ram  Updated AssocArr by replacing $? to support return value above 255
#        2010-01-13    # Anatoly Bondyuk    Added code to get of the support of reception of the list of users (including services LDAP, NIS, NIS +) by help of system functions getent and lsuser (lsgroup)
#        2010-02-01    # Anatoly Bondyuk    Fixed the issue with the checking of the passwd file
#        2010-03-01    # Anatoly Bondyuk    Fixed the issue with the checking of SSH-parameters (not correct usage of the command cut)
#        2010-03-05    # Anatoly Bondyuk    Added the cleaning of hashes after working of NIS-piece of the code
#        2010-03-09    # Anatoly Bondyuk    Added the fix for the checking SUDO-aliases by the hostname with the help of a long hostname
#        2010-03-09    # Anatoly Bondyuk    Added the fix for checking SUDO-privileges for NIS's accounts
#        2010-03-11    # Anatoly Bondyuk    Added the possibility to analyze the alternative SSHD file and the SUDO file on SunOS
# V4.6   2010-04-08    # Vladislav Tembekov Added code to fetch Ids from LDAP
#        2010-04-27    # Vladislav Tembekov Extend debug information
#        2010-04-30    # Vladislav Tembekov Optimized Parse_User and Parse_Grp functions
#        2010-05-03    # Vladislav Tembekov Added new option (-q) to support FQDN in MEF file
# V4.6.2 2010-05-21    # Vladislav Tembekov Fixed code to Ignore SUDOALL if "ALL=!somewhat" rule found
#        2010-05-26    # Vladislav Tembekov Added more default paths for search sudoers file
# V4.6.3 2010-06-15    # Vladislav Tembekov Fixed the issue with -m option. Added code to remove temp files.
#        2010-06-16    # Vladislav Tembekov Fixed the issue with -p and -g options. Added -a option(noautoldap) 
# V4.6.4 2010-07-05    # Vladislav Tembekov Updated code to checksum calculation. Added NIS+ support.
# V4.6.5 2010-08-04    # Vladislav Tembekov Fixed host name bug. Changed logging. Fixed some minor bugs.
# V4.6.6 2010-09-07    # Vladislav Tembekov Updated processing LDAP userids.
# V4.6.7 2010-09-15    # Vladislav Tembekov Fixed possible issue with user state
# V4.6.8 2010-10-15    # Vladislav Tembekov Changed default output file directory.
# V4.6.9 2010-12-02    # Vladislav Tembekov Additional check of privileged groups was added
# V4.7   2010-12-16    # Vladislav Tembekov Added code to process include and includedir directives in sudoers file
# V4.7.1 2011-01-04    # Vladislav Tembekov Change level of some messages from error to warning
# V4.7.2 2011-01-19    # Vladislav Tembekov Fixed issue on HPUNIX with hostname length limitation
# V4.7.3 2011-01-24    # Vladislav Tembekov Added customerOnly(-K) and ibmOnly(-I) options
# V4.7.4 2011-01-28    # Vladislav Tembekov Added code to print user last logon date for Linux, Solaris
# V4.7.5 2011-02-07    # Vladislav Tembekov Added code to filter LDAP users on AIX
# V4.7.6 2011-02-18    # Vladislav Tembekov Added check filename in preparsesudoers 
# V4.7.7 2011-02-21    # Vladislav Tembekov Fixed issue with hostname, Fixed issue with \n in lastlogindate
# V4.7.8 2011-03-03    # Vladislav Tembekov Added code to remove "|" in gecos field
# V4.7.9 2011-03-14    # Vladislav Tembekov Added -O(owner) flag to change output file permission
# V4.8   2011-03-29    # Vladislav Tembekov Added -D flag to disable print last logon date, added flag in print function arg to work in raw mode 
# V4.8.1 2011-04-04    # Vladislav Tembekov Added check for LDAP IDs in passwd file
# V4.8.2 2011-04-06    # Vladislav Tembekov Added code to print IDs SUDO-aliases
# V4.8.3 2011-04-11    # Vladislav Tembekov Fixed privileged group field issue
#===============================================================================

VERSION="V4.8.3"

################################################################################
SIG=""
HOST=""
FQDN=0
DEBUG=0
EXIT_CODE=0
OUTPUTFILE=""
KNOWPAR=""
UNKNOWPAR=""
#################################################################################
function logMsg
{
  level=$1
  msg=$2
  echo "[$level] $msg"
}

function logDiv
{
  logMsg "INFO" "==========================================="
}

function logAbort
{
  logMsg "ERROR" "$1"
  logFooter
  exit 9
}

function logDebug
{
  if [[ $DEBUG -ne 0 ]]; then
    logMsg "DEBUG" "$1"
  fi
}

function logInfo
{
  logMsg "INFO" "$1"
}

function logMsgVerNotSupp
{
  logMsg "ERROR" "The found version of the Sub System is not supported by the given script."
}

function logHeader
{
  STARTTIME=`date +%Y-%m-%d-%H.%M.%S`
  
  logInfo "UID EXTRACTOR EXECUTION - Started"
  logInfo "START TIME: $STARTTIME"
  logDiv
  logInfo "URT Global OS Extractor"
  logDiv
}

function logPostHeader
{
  if [[ $KNOWPAR != "" ]]; then
    logInfo "Following parameters will be processed: $KNOWPAR"
  fi
  
  if [[ $UNKNOWPAR != "" ]]; then
    logMsg "WARN" "Following unknown parameters will not be processed: $UNKNOWPAR"
  fi
  
  logDiv
  logInfo "SCRIPT NAME: ${1#./}"
  logInfo "SCRIPT VERSION: $VERSION"
  logInfo "CKSUM(unix): $CKSUM"
  logInfo "OS CAPTION: `uname`"
  logInfo "OS VERSION: `uname -r`"
  logInfo "HOSTNAME: $HOST"
  logInfo "CUSTOMER: $CUSTOMER"
  logInfo "OUTPUTFILE: $OUTPUTFILE"
  logInfo "SIGNATURE: $SIG"
  
  logInfo "IS_AG: no"
  logInfo "IS_ALLUSERIDS: yes"
  
  if [ $FQDN -ne 0 ]; then
    logInfo "IS_FQDN: yes"
  else
    logInfo "IS_FQDN: no"
  fi

  if [ $DEBUG -ne 0 ]; then
    logInfo "IS_DEBUG: yes"
  else
    logInfo "IS_DEBUG: no"
  fi
  
  logDiv
  
  logInfo "EXTRACTION PROCESS - Started"
  if [ $DEBUG -ne 0 ]; then
    logDiv
  fi
}

function logFooter
{
  if [ $DEBUG -ne 0 ]; then
    logDiv
  fi
  
  logInfo "EXTRACTION PROCESS - Finished"
  logDiv
  if [[ $EXIT_CODE -lt 2 ]]; then
    logInfo "The mef3 data has been collected"
  else
    logInfo "The mef3 data has not been collected"
    `rm -f $OUTPUTFILE`
  fi
  logDiv
  logInfo "Time elapsed: `echo $SECONDS`"
  logDiv
  
  if [[ $EXIT_CODE -lt 2 ]]; then
    logInfo "The report has been finished with success" 
  else
    logInfo "The report has been finished without success" 
  fi
    
  logInfo "General return code: $EXIT_CODE"
  logInfo "UID EXTRACTOR EXECUTION - Finished"
#################### custom addition of ftp
ftp -in 172.31.8.146<<EOF
user nmon nmon
lcd /tmp
cd /home/nmon/mef3_output
mput $CUSTOMER""_""$DATE""_""$HOST.mef3"
EOF
#####################
#  `cp $OUTPUTFILE /usr/scripts/Security/URT/`;
}
#####################################################################################

### Start of AssocArr lib
# Associative array routines
# @(#) AssocArr 1.5
# 1993-06-25 john h. dubois iii (john@armory.com)
# 1993-07-09 Changed syntax of AStore so that these functions can be used
#            for set operations.
# 1994-06-26 Added append capability to AStore
# 1995-10-19 Keep track of highest element used, and pass it to Ind
# 2000-11-26 Added m_AStore and APrintAll
# 2001-06-24 Avoid some evals by using (()) to dereference integer var names.
# 2001-07-14 Fixed bug in AStore
# 2002-01-30 Fixed bugs in AGet and ADelete
# 2002-02-03 Added ANElem
# 2002-11-14 ksh93 compatibility fix
# 2003-07-27 1.5 Added AInit
#
# These routines use two shell arrays and an integer variable for each
# associative array:
# For associative array "foo", the values are stored in foo_val[1..255] and the
# indices (free form character strings) are stored in foo_ind[].
# The free pointer is stored in foo_free.  It has the value of the lowest index
# that may be free. The end pointer is stored in foo_end; it has the value of
# the highest index used.
# Only 255 values can be stored.
# Arrays must have names that are valid shell variable names.
# A null array index is not allowed.

# Usage: Ind <arrayname> <value> [[<nsearch>] <firstelem>]
# Returns the index of the first element of <arrayname> that has value <value>.
# Note, <arrayname> is a full ksh array name, not an associate array name as
# used by this library.
# Returns 0 if it is none found.
# Works only for indexes 1..255.
# If <nsearch> is given, the first <nsearch> elements of the array are
# searched, with only nonempty elements counted.
# If not, the first n nonempty elements are searched,
# where n is the number of elements in the array.
# If a fourth argument (<firstelem>) is given, it is the index to start with;
# the search continues for <nsearch> elements.
# Element zero should not be set.
function Ind
{
  integer NElem ElemNum=${5:-1} NumNonNull=0 num_set
  typeset Arr=$1 Val=$2 Res=$3 ElemVal

  eval num_set=\${#$Arr[*]}
    if [[ $# -eq 4 ]]; then
      NElem=$4
      # No point in searching more elements than are set
      (( NElem > num_set )) && NElem=num_set
    else
    NElem=$num_set
  fi
  while (( ElemNum <= 99999 && NumNonNull < NElem )); do
    eval ElemVal=\"\${$Arr[ElemNum]}\"
    if [[ $Val = $ElemVal ]]; then
      eval ${Res}=$ElemNum
    return 1
  fi
  [[ -n $ElemVal ]] && ((NumNonNull+=1))
  ((ElemNum+=1))
  done
  return 0
}

# Usage: AInit <arrayname> <index1> <value1> [<index2> <value2>] ...
# Stores each value in associative array <arrayname> under the associated
# index.  Up to 255 index/value pairs may be given.
# <arrayname> is treated as though it is initially empty.
# Return value is 0 for success, 1 for failure due to full array,
# 2 for failure due to bad index or arrayname, 3 for bad syntax
function AInit
{
  typeset Arr=$1
  integer Ind

  shift
  # Arr must be a valid ksh variable name
  #[[ $Arr != [[:alpha:]_]*([[:word:]]) ]] && return 2
  (( $# % 2 != 0 )) && return 3

  Ind=1
  while (( $# > 0 && Ind < 100000 )); do
    Index=$1
    Val=$2
  [[ -z $Index ]] && return 2
  eval ${Arr}_ind[Ind]=\$Index ${Arr}_val[Ind]=\$Val
  ((Ind+=1))
  shift 2
  done
  (( ${Arr}_free=Ind ))
  (( ${Arr}_end=Ind-1 ))
  (( $# > 0 )) && return 1
  return 0
}

# Usage: AStore <arrayname> <index> [<value> [<append>]]
# Stores value <value> in associative array <arrayname> with index <index>
# If no <value> is given, nothing is stored in the value array.
# This can be used for set operations.
# If a 4th argument is given, the value is appended to the current value
# stored for the index (if any).
# Return value is 0 for success, 1 for failure due to full array,
# 2 for failure due to bad index or arrayname, 3 for bad syntax
function AStore
{
  typeset Arr=$1 Index=$2 Val=$3
  integer Used Free=0 NumArgs=$# arrEnd
  NumInd=0
  [[ -z $Index ]] && return 2
  # Arr must be a valid ksh variable name
  #    [[ $Arr != [[:alpha:]_]*([[:word:]]) ]] && return 2

  if eval [[ -z \"\$${Arr}_free\" ]]; then      # New array
    # Start free pointer at 1 - we do not use element 0
    Free=1
    arrEnd=0
    NumInd=0
  else  # Extant array
    (( arrEnd=${Arr}_end ))
    Ind ${Arr}_ind "$Index" NumInd $arrEnd
  fi
  # If the supplied <index> is not in use yet, we must find a slot for it
  # and store the index in that slot.
  if [[ NumInd -eq 0 ]]; then
    if [[ Free -eq 0 ]]; then # If this is not a newly created array...
      eval Used=\${#${Arr}_ind[*]}
      if [[ Used -eq 99999 ]]; then
        logMsg "ERROR" "Adding $Val to Array:$Arr is FULL: $Used of 99999"
        EXIT_CODE=1
        return 1 # No space available
      fi
      (( Free=${Arr}_free ))
    fi
    # Find an unused element
    while eval [[ -n \"\${${Arr}_ind[Free]}\" ]]; do
      ((Free+=1))
      (( Free > 99999 )) && Free=1  # wrap
    done
    NumInd=Free
    (( NumInd > arrEnd )) && arrEnd=NumInd
    (( ${Arr}_free=Free ))
    (( ${Arr}_end=$arrEnd ))
    # Store index
    eval ${Arr}_ind[NumInd]=\$Index
  fi
  case $NumArgs in
    2) return 0;;     # Set no value
    3) eval ${Arr}_val[NumInd]=\$Val;;  # Store value
    4)  # Append value
      eval ${Arr}_val[NumInd]=\"\${${Arr}_val[NumInd]}\$Val\";;
    *) return 3;;
  esac
  return 0
}

# Usage: m_AStore <arrayname> <append> <index> <value> [<index> <value> ...]
# Stores multiple values in associative array <arrayname>.
# For each <index>,<value> pair, <value> is stored under the index <index>
# in associate array <arrayname>.
# If <append> is non-null, values are appended to current values
# stored for indexes (if any).
# See AStore for details.
# On success, 0 is returned.
# If an error occurs, array insertion stops and the error returned by
# AStore is returned.
function m_AStore
{
  typeset Arr=$1 Append=$2

  shift 2
  while (( $# > 0 )); do
    AStore "$Arr" "$1" "$2" $Append || return $?
    shift 2
  done
  return 0
}

# Usage: AGet <arrayname> <index> <var>
# Finds the value indexed by <index> in associative array <arrayname>.
# If there is no such array or index, 0 is returned and <var> is not touched.
# Otherwise, <var> (if given) is set to the indexed value and the numeric index
# for <index> in the arrays is returned.
function AGet
{
  typeset Arr=$1 Index=$2 Var=$3 End
  NumInd=0
  # Can't use implicit integer referencing on ${Arr}_end here because it may
  # not be set yet.
  eval End=\$${Arr}_end
  [[ -z $End ]] && return 0

  Ind ${Arr}_ind "$Index" NumInd $End
  if (( NumInd > 0 )) && [[ -n $Var ]]; then
    eval $Var=\"\${${Arr}_val[NumInd]}\"
  fi
  return $NumInd
}

# Usage: AUnset <arrayname>
# Removes all elements from associative array <arrayname>
function AUnset
{
  typeset Arr=$1
  eval unset ${Arr}_ind ${Arr}_val ${Arr}_free
}

# Usage: ADelete <arrayname> <index>
# Removes index <index> from associative array <arrayname>
# Returns 0 on success, 1 if <index> was not an index of <arrayname>
function ADelete
{
  typeset Arr=$1 Index=$2 End
  NumInd=0
  # Can't use implicit integer referencing on ${Arr}_end here because it may
  # not be set yet.
  eval End=\$${Arr}_end

  Ind ${Arr}_ind "$Index" NumInd $End
  if (( NumInd > 0 )); then
    eval unset ${Arr}_ind[NumInd] ${Arr}_val[NumInd]
    (( NumInd < ${Arr}_free )) && (( ${Arr}_free=NumInd ))
    return 0
  else
    return 1
  fi
}

# Usage: AGetAll <arrayname> <varname>
# All of the indices of array <arrayname> are stored in shell array <varname>
# with indices starting with 0.
# The total number of indices is returned.
function AGetAll
{
  integer NElem ElemNum=1 NumNonNull=0
  typeset Arr=$1 VarName=$2 ElemVal

  eval NElem=\${#${Arr}_ind[*]}
    while (( ElemNum <= 99999 && NumNonNull < NElem )); do
      eval ElemVal=\"\${${Arr}_ind[ElemNum]}\"
      if [[ -n $ElemVal ]]; then
        eval $VarName[NumNonNull]=\$ElemVal
        ((NumNonNull+=1))
      fi
      ((ElemNum+=1))
    done
  return $NumNonNull
}

# Usage: APrintAll <arrayname> [<sep>]
# For each value stored in <arrayname>, a line containing the index and value
# is printed in the form: index<sep>value
# If <sep> is not passed, '=' is used.
# The total number of indices is returned.
function APrintAll
{
  integer NElem ElemNum=1 NumNonNull=0
  typeset Arr=$1 Sep=$2 ElemVal ElemInd

  (( $# < 2 )) && Sep="="

  eval NElem=\${#${Arr}_ind[*]}
    while (( ElemNum <= 99999 && NumNonNull < NElem )); do
      eval ElemInd=\"\${${Arr}_ind[ElemNum]}\" \
      ElemVal=\"\${${Arr}_val[ElemNum]}\"
      if [[ -n $ElemInd ]]; then
        print -r -- "$ElemInd$Sep$ElemVal"
        ((NumNonNull+=1))
      fi
      ((ElemNum+=1))
    done
  return $NumNonNull
}

# Usage: ANElem <arrayname>
# The total number of indices in <arrayname> is returned.
function ANElem
{
  eval return \${#${1}_ind[*]}
}

# Read a defaults file
# Usage: ReadDefaults filename var ...
# Any of the named vars that are listed in the file are set globally
function ReadDefaults
{
  typeset Defaults var file=$1
  shift

  set_Avars Defaults "$file"
  for var in "$@"; do
    AGet Defaults $var $var
  done
}

# set_Avars: store variable assignments in an associative array.
# 1993-12-28 John H. DuBois III (john@armory.com)
# Converts values to forms that won't be messed with by the shell.
# Usage: set_Avars [-c] array-name [filename ...]
# where the lines in filename (or the input) are of the form
# var=value
# value may contain spaces, backslashes, quote characters, etc.;
# they will become part of the value assigned to index var.
# Lines that begin with a # (optionally preceded by whitespace)
# and lines that do not contain a '=' are ignored.
# Variables are stored in associative array array-name.
# If -c is given, an error message is printed & the program is exited
# if an attempt is made to set a value for a parameter that has already
# been set.

function set_Avars
{
  typeset Arr store

  if [[ $1 = -c ]]; then
    store=ChkStore
    shift
  else
    store=AStore
  fi
  Arr=$1
  shift
  for file; do
    if [[ ! -r $file ]]; then
      logMsg "WARNING" "$file: Could not open."
      return 1
    fi
  done
  # return exit status of eval
  eval "$(sed "
/^[ 	]*#/d
  /=/!d
  s/'/'\\\\''/g
  s/=/ '/
  s/$/'/
  s/^/$store $Arr /" "$@")"
}

# Usage: ChkStore <arrname> <index> <value>
# Exit if <index> is already set
function ChkStore
{
  typeset arrname=$1 index=$2 value=$3

  if AGet $arrname $index; then
    # 0 return means index not found
    AStore $arrname $index "$value"
  else
    logAbort "$index already set.  Exiting."
  fi
}

function checkforldappasswd
{
  FPASSWDFILE=$PASSWDFILE
  while read line; do
    matched=`echo $line|grep ^+|wc -l`
    if [[ $matched -gt 0 ]]; then
      return 0 
    fi
  done < $FPASSWDFILE
  return 1
}


function Parse_User
{
  ### extracting primary groups from passwd file
  if [[ $PROCESSNIS -eq 1 ]]; then
    FPASSWDFILE=$NISPASSWD
  fi

  if [[ $PROCESSLDAP -eq 1 ]]; then
    FPASSWDFILE=$LDAPPASSWD
  fi	
    
  if [[ $PROCESSNIS -eq 0 && $PROCESSLDAP -eq 0 ]]; then
    FPASSWDFILE=$PASSWDFILE
  fi

  if [[ $IS_ADMIN_ENT_ACC -eq 1 && $NIS -eq 0 && $LDAP -eq 0 && $NOAUTOLDAP -eq 0 ]]; then
    if [[ $OS = "Linux" ]]; then
      `getent passwd > $ADMENTPASSWD`
      FPASSWDFILE=$ADMENTPASSWD
    elif [[ $OS = "SunOS" ]]; then
      `getent passwd > $ADMENTPASSWD`
      FPASSWDFILE=$ADMENTPASSWD
    fi
  fi

  logDebug "Reading PASSWDFILE: $FPASSWDFILE"

  while IFS=: read -r userid passwd uid gid gecos home shell
    do
      logDebug "Parse_User->read userid=$userid passwd=$passwd uid=$uid gid=$gid gecos=$gecos home=$home shell=$shell"
      if [[ $PROCESSNIS -eq 0 && $LDAP -eq 0 ]]; then
        matched=`echo $userid|grep ^+|wc -l`
        if [[ $matched -gt 0 ]]; then
          if [[ $LDAP -eq 0 ]]; then
            logInfo "User $userid is excluded from output file use, -L option to lookup LDAP NetGrp IDs"
            continue
          fi
          matched=`echo $userid|grep ^+@|wc -l`
          if [[ $matched -gt 0 ]]; then
            Parse_LDAP_Netgrp $userid
            continue
          else
            userid=`echo $userid | tr -d '+'`
            AGet PasswdUser "${userid}" testvar
            if [[ $? -eq 0 ]]; then
              Parse_LDAP_Netuser $userid
            else
              logDebug "User $userid Already exist"
            fi
          fi
        fi
      fi

    AStore PasswdUser ${userid} "$userid"
    AGet primaryGroupUsers ${gid} testvar
    if  [[ $? -eq 0 ]]; then
      AStore primaryGroupUsers ${gid} "$userid"
    else
      AStore primaryGroupUsers ${gid} ",$userid" append
    fi
  done < $FPASSWDFILE
  `rm -f $ADMENTPASSWD`
}

function Parse_Grp
{
  if [[ $PROCESSNIS -eq 1 ]]; then
    FGROUPFILE=$NISGROUP
  fi

  if [[ $PROCESSLDAP -eq 1 ]]; then
    FGROUPFILE=$LDAPGROUP
  fi	
        
  if [[ $PROCESSNIS -eq 0 && $PROCESSLDAP -eq 0 ]]; then
    FGROUPFILE=$GROUPFILE
  fi

  if [[ $IS_ADMIN_ENT_ACC -eq 1 && $NIS -eq 0 && $LDAP -eq 0  && $NOAUTOLDAP -eq 0 ]]; then
    if [[ $OS = "Linux" ]]; then
      `getent group > $ADMENTGROUP`
      FGROUPFILE=$ADMENTGROUP
    elif [[ $OS = "SunOS" ]]; then
      `getent group > $ADMENTGROUP`
      FGROUPFILE=$ADMENTGROUP
    fi
  fi

  logDebug "Reading GROUPFILE: $FGROUPFILE"

  while IFS=: read -r group gpasswd gid members
    do
      logDebug "Parse_Grp->read group=$group gpasswd=$gpasswd gid=$gid members=$members"
      AStore groupGIDName ${gid} "$group"
      
      allusers=""
      AGet primaryGroupUsers ${gid} allusers

      logDebug "Reading in users with $group as a primary group"
      logDebug "grpgid: $gid"
      logDebug "$group pgusers: $allusers"

      if [[ $allusers != "" ]]; then
        if [[ $members != "" ]]; then
          allusers=$allusers",$members"
        else
          allusers=$allusers
        fi
      else
        allusers="$members"
      fi

      logDebug "Reading in $group memberlist from group file"
      logDebug "$group allusers: $allusers"
      logDebug "Uniquifying list"

      AUnset UniqueUsers
      uniqueusers=""
      IFS=,;for nextuser in ${allusers}
        do
          AGet UniqueUsers $nextuser testvar
          if  [[ $? -eq 0 ]]; then
            AStore UniqueUsers  $nextuser "$nextuser"
            if [[ $uniqueusers != "" ]]; then
              uniqueusers=$uniqueusers",$nextuser"
            else
              uniqueusers="$nextuser"
            fi
          else
            continue
          fi
      done
  IFS=" "
  logDebug "Uniqufied allusers: $uniqueusers"
  ## storing users ist whihc includes primary groups
  AStore ALLGroupUsers ${group} "$uniqueusers"

  IFS=,;for nextuser in ${uniqueusers}
    do
      AGet AllUserGroups ${nextuser} testvar
      if  [[ $? -eq 0 ]]; then
        AStore AllUserGroups ${nextuser} "$group"
      else
        is_dublicate_checker=0
        for bufgroup in ${testvar}
          do
            if [[ $bufgroup = $group ]]; then
              is_dublicate_checker=1
              break
            fi
          done
        if [[ $is_dublicate_checker -eq 0 ]]; then
          AStore AllUserGroups ${nextuser} ",$group" append
        fi
      fi
    done
  IFS=" "
  matched=0
  if [[ $OS = "Linux" ]]; then
    logDebug "Found Linux"
      matched=`echo $group|egrep $PRIVGROUPS|wc -l`   #V4.5 PRIV group in linux
    if [[ $gid -lt 100 ]]; then
      logDebug "Found privileged group $group $gid < 100"
      logDebug "Adding group: $group:lt100"
      matched=1
    fi
  else
    matched=`echo $group|egrep $PRIVGROUPS|wc -l`
  fi

  if [[ $matched -gt 0 ]]; then
    logDebug "Found Priv group: ----$group""----$members"
    IFS=,;for nextuser in ${uniqueusers}
    do
      AGet privUserGroups ${nextuser} testvar
      if  [[ $? -eq 0 ]]; then
        AStore privUserGroups ${nextuser} "$group"
      else
        is_dublicate_checker=0
        for bufgroup in ${testvar}
        do
          if [[ $bufgroup = $group ]]; then
            is_dublicate_checker=1
            break
          fi
        done

        if [[ $is_dublicate_checker -eq 0 ]]; then
          AStore privUserGroups ${nextuser} ",$group" append
        fi
      fi
    done
    IFS=" "
  fi
  done < $FGROUPFILE
  `rm -f $ADMENTGROUP`
}

function parse_LDAP_grp
{
  DATA=`$LDAPCMD -LLL -h $LDAPSVR -p $LDAPPORT -b $LDAPBASE objectClass=posixGroup cn gidNumber memberUid >> $ldap_tmp`
  awk "  /^cn:/ { print }" $ldap_tmp | cut -d" "  -f2 > $ldap_tmp1
  
  group=""
  gid=""
  gmem=""

  IFS=" "
  while read group; do
    attr=`awk " { RS="\n\n" }  /^dn: cn=$group,/ { print }" $ldap_tmp | sed 's/: /:/g'`
    logDebug "parse_LDAP_grp->read attr=$attr"
    gmem=""
    if echo "$attr" | grep -i "gidNumber:" > /dev/null; then
      gid=$(echo "$attr" | sed -n 's/^gidNumber:\(.*\)/\1/p')
    fi
    if echo "$attr" | grep -i "memberUid:" > /dev/null; then
      gmem=$(echo "$attr" | sed -n 's/^memberUid:\(.*\)/LDAP\/\1/p' | tr ['\n'] [,] )
    fi
    logDebug "parse_LDAP_grp->processed group=$group gid=$gid gmem=$gmem"
    echo "$group::$gid:$gmem" >> $LDAPGROUP
    group=""
    gid=""
    gmem=""
  done < $ldap_tmp1
}

function get_state
{
  typeset ckid=$1 ostype=$2
  ckid=$(echo $1|sed 's/\//\\\//g')
  state="Enabled"
  if [[ $ostype = "AIX" ]]; then
    crypt=`awk "{ RS="\n\n" } /^$ckid:/ { print }" $SPASSWD|grep password|cut -d" " -f3`
    if [[ $crypt = "*" ]]; then
      #logDebug "AIX SPASSWD password * DISABLED $ckid: crypt:$crypt"
      state="Disabled"
    fi
    locked=`awk "{ RS="\n\n" } /^$ckid:/ { print }" $SECUSER|grep account_locked|cut -d" " -f3`
    if [[ $locked = "true" ]]; then
      #logDebug "AIX SECUSER account_locked false DISABLED $ckid: locked:$locked"
      state="Disabled"
    fi
  else
    if [  -r $SPASSWD ]; then
      crypt=`grep ^$ckid: $SPASSWD|cut -d: -f2`
      # check for user disabled by LOCKED, NP, *LK*, !!, or * in password field
      if [[ $crypt = "LOCKED" ]]; then
        state="Disabled"
      fi
      if [[ $crypt = "*" ]]; then
        #logDebug "SPASSWD DISABLED $ckid: crypt:$crypt"
        state="Disabled"
      fi
      if echo "$crypt" | grep "*LK*" > /dev/null; then    #V 4.5
        state="Disabled"
      fi
      if [[ $crypt = "NP" ]]; then
        state="Disabled"
      fi
      if echo "$crypt" | grep "^!" > /dev/null; then
        state="Disabled"
      fi
    fi
  fi
  echo $state
}


# V2.6 iwong
function hpux_get_state
{
    typeset ckid=$1 ostype=$2 
    state="Enabled"
    # process shadow file if it exists
    if [  -r $SPASSWD ]; then
      crypt=`grep ^$ckid: $SPASSWD|cut -d: -f2`

      # check for user disabled by LOCKED, NP, *LK*, !!, or * in password field
      if [[ $crypt = "LOCKED" ]]; then
        #logDebug "DEBUG: HPUX SPASSWD DISABLED $ckid: crypt:$crypt" >&2
        state="Disabled"
      fi
      if [[ $crypt = "*" ]]; then
        #logDebug "HPUX SPASSWD DISABLED $ckid: crypt:$crypt" >&2
        state="Disabled"
      fi
      if [[ $crypt = "*LK*" ]]; then
        #logDebug "HPUX SPASSWD DISABLED $ckid: crypt:$crypt" >&2
        state="Disabled"
      fi
      if [[ $crypt = "NP" ]]; then
        #logDebug "HPUX SPASSWD DISABLED $ckid: crypt:$crypt" >&2
        state="Disabled"
      fi
      #if [[ $crypt = "!!" ]]; then
      if echo "$crypt" | grep "^!" > /dev/null; then          
        #logDebug "HPUX SPASSWD DISABLED $ckid: crypt:$crypt" >&2
        state="Disabled"
      fi
      ## additional check for HP TCB systems
    fi
    # peform getprpw check if TCB machine
    if [[ $TCB_READABLE -eq 1 ]]; then
      lockout=`/usr/lbin/getprpw -m lockout $ckid`
      matched=`echo $lockout|grep 1|wc -l`
      if [[ $matched -gt 0 ]]; then
        #logDebug "HPUX getprpw DISABLED $ckid: $lockout" >&2
        state="Disabled"
      #else
        #logDebug "HPUX getprpw $ckid: $lockout" >&2
      fi
    fi
    echo $state
}

function ProcessUser_Alias
{
   typeset alias=$1 
   logDebug "Starting ProcessUser_Alias:User_Alias: $alias"

   AGet aliasUsers ${alias} aliasusers

   ## process throu list of users
   IFS=,;for nextuser in ${aliasusers}
    do
      ## added code to process groups in the user_alias
      if echo "$nextuser" | grep "^%" >/dev/null; then 
      ## parse out % in group name
        group=`echo ${nextuser}|tr -d %`
        logDebug "ProcessUser_Alias: Found GROUP in User_Alias->$group"

        ## check if goup already read
        AGet sudoGroups $group testvar
        if  [[ $? -eq 0 ]]; then
           ## process through users in the group
          AGet ALLGroupUsers $group uniqueusers
          if [[ $? -eq 0 ]]; then
            logMsg "WARNING" "Invalid group in $SUDOERFILE in User_Alias $alias: $group"
            EXIT_CODE=1
            #let errorCount=errorCount+1
          else
            AStore sudoGroups  ${group} "$alias" 
            logDebug "ProcessUser_Alias: SUDOERS: User_Alias Adding group: $group:$alias"
            IFS=,;for nextu in ${uniqueusers}
            do
              AGet sudoUserGroups ${nextu} testvar
              if  [[ $? -eq 0 ]]; then
                AStore sudoUserGroups ${nextu} "$group" 
                #print "AStore add to sudoUserGroups RC=$?"
              else
                AStore sudoUserGroups ${nextu} ",$group" append
                #print "AStore add to sudoUserGroups RC=$?"
              fi
            done
            IFS=" "
         fi
        else
          logDebug "ProcessUser_Alias: WARNING: User_Alias group: $group read in already"
          continue
        fi
      else
        AGet PasswdUser $nextuser testvar
        if [[ $? -eq 0 ]]; then
           logMsg "WARNING" "Invalid user in $SUDOERFILE in User_Alias $alias: $nextuser"
          EXIT_CODE=1
          #let errorCount=errorCount+1
        else
           userAlias=$nextuser":"$alias
          AGet sudoUsers ${nextuser} testvar
          if  [[ $? -eq 0 ]]; then
            AStore sudoUsers ${nextuser} ${nextuser}
            logDebug "ProcessUser_Alias: User_Alias Adding user to sudoUsers: $userAlias"
          else 
            logDebug "ProcessUser_Alias: WARNING: user already in sudoUsers: $userAlias"
            continue
          fi
        fi
      fi
   done
   IFS=" "
   logDebug "Finished ProcessUser_Alias:User_Alias: $alias"
}

Remove_Labeling_Delimiter()
{
  typeset labellingData=$1
  
  outLabellingData=`echo "$labellingData" | sed "s/|/ /g"`
  echo "$outLabellingData"
  return 0
}

GetURTFormat()
{
  typeset _gecos=$1

  userstatus="C"
  userccc=$USERCC
  userserial=""
  usercust=""
  usercomment=$_gecos

  ## LOOK FOR CIO Format
  matched=`echo $_gecos | grep -i "s\=" | wc -l`
  if [[ $matched -gt 0 ]]; then
    serialccc=$(echo $gecos | tr "[:upper:]" "[:lower:]" | sed -n 's/.*\(s=[a-zA-Z0-9]*\).*/\1/p')
    serial=$(echo $serialccc|cut -c3-8)
    ccc=$(echo $serialccc|cut -c9-11)

    if [[ ${#serialccc} -ge 11 ]]; then
      userserial=$serial
      userccc=$ccc
      userstatus="I"
      usercust=""
      usercomment=$_gecos
    fi
  fi

  ## LOOK FOR IBM SSSSSS CCC Format
    matched=`echo $_gecos | grep "IBM [a-zA-Z0-9]\{6\} [a-zA-Z0-9]\{3\}" | wc -l`
  if [[ $matched -gt 0 ]]; then
    userstatus="I"

    oIFS="$IFS"; IFS=' '
    set -A tokens $_gecos
    IFS="$oIFS"

    count=0
    while(( $count < ${#tokens[*]} )); do
    if [[ ${tokens[$count]} = "IBM" ]]; then
      if [[ count+3 -gt ${#tokens[*]} ]]; then
        break
      fi

      serial=${tokens[$count+1]}
      ccc=${tokens[$count+2]}
      if [[ ${#serial} -ne 6 ]]; then
        break
      fi
      if [[ ${#ccc} -lt 3 ]]; then
        break
      else
      ccc3=$(echo $ccc}|cut -c1-3)
    fi

    userserial=$serial
    userccc=$ccc3
    userstatus="I"
    usercomment=$_gecos
    break
  fi
  let count=count+1
  done
  fi

  usergecos="$userccc/$userstatus/$userserial/$usercust/$usercomment"

  ## LOOK FOR URT Format
  matched=`echo $_gecos | grep ".\{2,3\}\/.\{1\}\/" | wc -l`
  if [[ $matched -gt 0 ]]; then
    usergecos=$_gecos
  fi
  IFS=" "

  usergecos=`Remove_Labeling_Delimiter "$usergecos"`

  echo "$usergecos"
}

function preparsesudoers
{
  typeset sudo_file=$1
  typeset tmp_sudo=$2
  typeset include_file=""
  typeset include_dir=""
  
  logDebug "Preprocess sudo file $sudo_file";
 `cat $sudo_file >> $tmp_sudo`
  while read nextline; do
    if echo "$nextline" | egrep -i "#includedir" > /dev/null; then
      include_dir=`echo "$nextline" | awk '{print $2}'`
      typeset content=`ls $include_dir`
      IFS="
      ";for include_file in $content
      do
        if [ ! -e $include_file ]; then
          logDebug "SUDOERS:$include_file is not a file"
          continue
        fi  
        
        if echo "$include_file" | grep -i "~$" > /dev/null; then
          logDebug "SUDOERS: Skip file $include_file"
          continue
        fi
        
        if echo "$include_file" | grep -i "\." > /dev/null; then
          logDebug "SUDOERS: Skip file $include_file"
          continue
        fi
        
        include_file=$include_dir$include_file
        if [ -d $include_file ]; then
          logDebug "SUDOERS:Skip directory $include_file"
          continue
        fi
        logDebug "SUDOERS: Found #includedir directive. $include_dir"
        preparsesudoers $include_file $tmp_sudo
      done
      IFS=" "    
      continue
    fi  
    
    if echo "$nextline" | egrep -i "#include" > /dev/null; then
      include_file=`echo "$nextline" | awk '{print $2}'`
      
      if [ ! -e $include_file ]; then
         logDebug "SUDOERS:$include_file is not a file"
         continue
      fi  
      
      if echo "$include_file" | grep -i "%h$" > /dev/null; then
        include_file=${include_file%%\%h}
        include_file=$include_file"$HOST"
        logDebug "SUDOERS: Add host name to sudo file $include_file"
      fi
      logDebug "SUDOERS: Found #include directive. $include_file"
      preparsesudoers $include_file $tmp_sudo
    fi
  done < $sudo_file
}

function Parse_Sudo
{
  typeset tmp_sudo_file="/tmp/sudoersfile.tmp"
  preparsesudoers $SUDOERFILE $tmp_sudo_file
  
  SUDOALL="2"
  # egrep removes comments
  # egrep removes netgroup id ( any id starting with +)
  # sed remove leading and trailing spaces
  # sed -e join line with backslash
  # sed replace = with blank
  # sed replace tab with blank
  # tr remove multiple spaces
  # sed delete blank lines
  # remove space between commas
  # remove space between =
  
  DATA=`egrep -v "^#" $tmp_sudo_file| sed 's/^\+\(.*\)/LDAP\/\1/g' | sed 's/^[    ]*//;s/[	 ]*$//'|sed -e :a -e '/\\\\$/N; s/\\\\\n//; ta'|sed 's/	/ /g'|tr -s '[:space:]'|sed '/^$/d'|sed 's/, /,/g'|sed 's/ ,/,/g'|sed 's/ =/=/g'|sed 's/= /=/g'>$TMPFILE` 

  while read nextline; do
    #echo  "SUDOERS: $nextline "
    set -A tokens `echo $nextline`
    logDebug "SUDOERS: ----> $nextline"
    case ${tokens[0]} in
      Cmnd_Alias ) continue ;;
      Runas_Alias )continue ;;
      Defaults )continue ;;
      ALL )
      if [[ $nextline = *+(\!)* ]]; then
        logMsg "WARNING" "Found ALL=!Cmnd_Alias $nextline"
        SUDOALL="0"
      else
      if [[ $SUDOALL -eq 2 ]]; then
        SUDOALL="1"
      fi
    fi
    continue
    ;;
    Host_Alias )
    set -A HAtokens `echo $nextline|sed 's/=/ /g'`
    alias=${HAtokens[1]}
    aliashosts=${HAtokens[2]}
    ## add alias name in to array
    logDebug "SUDOERS HOST ALIAS: $nextline"
    logDebug "SUDOERS HOST ALIAS: Found host alias: $alias"
    ## process throu list of hosts
    IFS=,;for nexthost in ${aliashosts}
      do
        logDebug "SUDOER HOST ALIAS: Host_Alias: $alias checking $nexthost = $HOST"
        ## added code to process groups in the user_alias
        if [[ $nexthost = $HOST || $nexthost = $LONG_HOST_NAME ]]; then
          AStore validHostAlias ${alias} $alias
          logDebug "SUDOER HOST ALIAS: Found valid Host_Alias $alias = $HOST"
          continue
        fi
      done
      IFS=" "
      ;;
      User_Alias )
      set -A UAtokens `echo $nextline|sed 's/=/ /g'`
      alias=${UAtokens[1]}
      aliasusers=${UAtokens[2]}
      ## add alias name in to array
      logDebug "SUDOERS USER ALIAS: $nextline"
      logDebug "SUDOERS USER ALIAS: Found user alias: $alias"
      AStore aliasUsers ${alias} $aliasusers
      
      IFS=,;for usr in $aliasusers
      do
        AGet UserAliasList $usr testvar
        if  [[ $? -ne 0 ]]; then
          testvar=$testvar",$aliasusers"
          AStore UserAliasList ${usr} $testvar
        else
          AStore UserAliasList ${usr} $alias
        fi    
       done   
      ;;
      * )
      #Checking to see if this is a valid host/Host_Alias/ALL
      logDebug "SUDOERS USER/GROUP: $nextline"
      PROCESS_LINE="0"

	  for nexttoken in ${nextline}
        do
          logDebug "SUDOERS USER/GROUP: checking nexttoken: $nexttoken"
          if echo "$nexttoken" | grep "=" >/dev/null; then
            hosttoken=`echo $nexttoken|cut -d"=" -f1`
            logDebug "SUDOERS USER/GROUP: FOUND nexttoken: $nexttoken"
            logDebug "SUDOERS USER/GROUP: FOUND hosttoken: $hosttoken"

            # process throu each hostname and Host_alias
            IFS=,;for nexthost in ${hosttoken}
              do
                logDebug "SUDOERS USER/GROUP: FOUND nexthost: $nexthost"
                ## process through users in the group
                ## Check to seeing if valid host_alias
                AGet validHostAlias $nexthost testvar
                if [[ $? -eq 0 ]]; then
                  logDebug "INFO: Not a valid Host_alias: $nexthost"
                else
                  logDebug "INFO: Found a valid Host_alias: $nexthost"
                  PROCESS_LINE="1"
                fi

              if [[ $nexthost = "ALL" ]]; then
                logDebug "INFO: Found ALL: $nexthost"
                PROCESS_LINE="1"
                elif [[ $nexthost = $HOST || $nexthost = $LONG_HOST_NAME ]]; then
                  logDebug "INFO: Found match hostname $HOST: $nexthost"
                  PROCESS_LINE="1"
                fi

                ## Check to seeing if valid hostname
              done
              IFS=" "
            fi
          done

          logDebug "SUDOERS: PROCESS_LINE ->$PROCESS_LINE"
          if [[ $PROCESS_LINE -eq 1 ]]; then
            tokenlist=${tokens[0]}

        if echo "$tokenlist" | grep "^\@" > /dev/null; then   # V4.5
              tokenlist=`echo ${tokenlist}|tr -d @`
              echo "$tokenlist is netgrp"
              AGet Netgrplist $tokenlist testvar
              if [[ $? -ne 0 ]]; then
                tokenlist=$testvar
                logDebug "SUDOERS USER: Adding netgrp list $tokenlist"
              fi
            fi

            IFS=,;for nexttoken in ${tokenlist}
              do

                ## process token if group
                if echo "$nexttoken" | grep "^%" >/dev/null; then
                  ## parse out % in group name
                  group=`echo ${nexttoken}|tr -d %`
                  logDebug "SUDOERS GROUP: Found GROUP ->$group"

                  AGet sudoGroups $group testvar
                  ## check if goup already read
                  if  [[ $? -eq 0 ]]; then
                    ## process through users in the group
                    AGet ALLGroupUsers $group uniqueusers
                    if [[ $? -eq 0 ]]; then
                      logMsg "WARNING" "Invalid group in $SUDOERFILE: $group"
                      #let errorCount=errorCount+1
                      EXIT_CODE=1
                    else
                    logDebug "SUDOERS GROUP: Adding group: $group:group"
                    AStore sudoGroups  ${group} "group"
                    IFS=,;for nextu in ${uniqueusers}
                      do
                        #echo "#------- values from ${nextuser}"
                        AGet sudoUserGroups ${nextu} testvar
                        if  [[ $? -eq 0 ]]; then
                          AStore sudoUserGroups ${nextu} "$group"
                          #print "AStore add to sudoUserGroups RC=$?"
                        else
                        AStore sudoUserGroups ${nextu} ",$group" append
                        #print "AStore add to sudoUserGroups RC=$?"
                      fi
                    done
                    IFS=" "
                  fi
                else
                logDebug "SUDODERS GROUP: WARNING: group: $group read in already"
                continue
              fi
              ## else process as user
            else
            nextuser=$nexttoken
            logDebug "SUDOERS USER: nextuser ->$nextuser"

            ## cheack if this is an user_alias
            AGet aliasUsers $nextuser testvar
            if  [[ $? -ne 0 ]]; then
              logDebug "SUDOERS USER:  Matched User_Alias->$nextuser"
              ProcessUser_Alias $nextuser
              continue
            fi
            AGet PasswdUser $nextuser testvar
            if [[ $? -eq 0 ]]; then
              logMsg "WARNING" "Invalid user in $SUDOERFILE: $nextuser"
              #let errorCount=errorCount+1
              EXIT_CODE=1
            else
            AGet sudoUsers $nextuser testvar
            if  [[ $? -eq 0 ]]; then
              AStore sudoUsers ${nextuser} "sudo"
              logDebug "SUDOERS USER: Adding user: $nextuser"
            else
            logDebug "SUDOERS USER: WARNING: user: $nextuser read in already"
            continue
          fi
        fi
      fi
    done
    IFS=" "
  fi
  ;;
  esac
  done < $TMPFILE
  if [[ $SUDOALL -eq 2 ]]; then
    SUDOALL="0"
  fi
  
  `rm -f $tmp_sudo_file`
}

Get_Last_Logon_User_Id() {
  typeset userID=$1

  LAST_LODIN_DATE=""

  if [[ $OS = 'Linux' ]]; then
    LOGIN_DATA=`lastlog -u $userID 2>/dev/null | grep "$userID" | grep -v grep`

    NEVER_LOGGED_IN=`echo "$LOGIN_DATA" | awk '{if($0 ~ /Never logged in/){print $0}}'`

    if [[ $LOGIN_DATA != "" && $NEVER_LOGGED_IN = "" ]]; then
      LAST_LOGIN_YEAR=`echo "$LOGIN_DATA" | awk '{print $9}' | tr -d '\n'`
      LAST_LOGIN_MONTH=`echo "$LOGIN_DATA" | awk '{print $5}' | tr -d '\n'`
      LAST_LOGIN_DAY=`echo "$LOGIN_DATA" | awk '{print $6}' | tr -d '\n'`
      LAST_LOGIN_TIME=`echo "$LOGIN_DATA" | awk '{print $7}' | tr -d '\n'`

      LAST_LODIN_DATE=$LAST_LOGIN_DAY" "$LAST_LOGIN_MONTH" "$LAST_LOGIN_YEAR
    fi
    elif [[ $OS = 'AIX' ]]; then
      LOGIN_DATA=`lsuser -f $userID 2>/dev/null | grep time_last_login | grep -v grep | sed -e "s/.*=//"`
      if [[ $LOGIN_DATA != "" ]]; then
        if [ -e $PERL ]; then
          LOGIN_DATA=`$PERL -e "print scalar(localtime($LOGIN_DATA))"`
        fi
      fi

      if [[ $LOGIN_DATA != "" ]]; then
        LAST_LOGIN_YEAR=`echo "$LOGIN_DATA" | awk '{print $5}' | tr -d '\n'`
        LAST_LOGIN_MONTH=`echo "$LOGIN_DATA" | awk '{print $2}' | tr -d '\n'`
        LAST_LOGIN_DAY=`echo "$LOGIN_DATA" | awk '{print $3}' | tr -d '\n'`
        LAST_LOGIN_TIME=`echo "$LOGIN_DATA" | awk '{print $4}' | tr -d '\n'`

        LAST_LODIN_DATE=$LAST_LOGIN_DAY" "$LAST_LOGIN_MONTH" "$LAST_LOGIN_YEAR
      fi
    else
        CURRENT_YEAR=`date +%Y`
        CURRENT_MONTH=`date +%b`

      ON_SINCE_DATA=`finger $userID 2>/dev/null | awk '{if($0 ~ /On since/){ printf( "%s,", $0 ) }}'`

      if [[ $ON_SINCE_DATA != "" ]]; then
      # Work with situation when user still works with an account 
	    ON_SINCE_DATA=`echo "$ON_SINCE_DATA" | sed -e "s/.*On since //" | sed -e "s/ on.*//"`			

        PROCESSING_DATA=`echo "$ON_SINCE_DATA" | awk '{ if ($0 ~ /,/) {print $0}}'`

        if [[ $PROCESSING_DATA != "" ]]; then
          # Found the last login year
          LAST_LOGIN_YEAR=`echo "$ON_SINCE_DATA" | awk '{print $4}' | tr -d '\n'`
          LAST_LOGIN_MONTH=`echo "$ON_SINCE_DATA" | awk '{print $2}' | tr -d '\n'`

                lastLoginMonth=""
                curLoginMonth=""

                AGet MNames "$LAST_LOGIN_MONTH"                
                if  [[ $? -ne 0 ]]; then
                    AGet MNames "$LAST_LOGIN_MONTH" lastLoginMonth
                fi

                AGet MNames "$CURRENT_MONTH"                
                if  [[ $? -ne 0 ]]; then
                    AGet MNames "$CURRENT_MONTH" curLoginMonth
                fi

                if [[ $lastLoginMonth != "" && $curLoginMonth != "" ]]; then
                    if [[ $lastLoginMonth -lt 7 && $curLoginMonth -gt 6 ]]; then
                        ((LAST_LOGIN_YEAR -= 1))
                    fi
                fi

          LAST_LOGIN_DAY=`echo "$ON_SINCE_DATA" | awk '{ if($3 ~ /,/){outString=substr($3, 0, length($3)-1);print outString;}else{print $3}}' | tr -d '\n'`
          LAST_LOGIN_TIME=""
	    else
                LAST_LOGIN_YEAR=`date +%Y`
                LAST_LOGIN_MONTH=`echo "$ON_SINCE_DATA" | awk '{print $1}' | tr -d '\n'`
                LAST_LOGIN_DAY=`echo "$ON_SINCE_DATA" | awk '{print $2}' | tr -d '\n'`
                LAST_LOGIN_TIME=`echo "$ON_SINCE_DATA" | awk '{print $3}' | tr -d '\n'`
        fi

        LAST_LODIN_DATE=$LAST_LOGIN_DAY" "$LAST_LOGIN_MONTH" "$LAST_LOGIN_YEAR
      fi

      LAST_LOGIN=`finger $userID 2>/dev/null | awk '{if($0 ~ /Last login/){ print $0 }}'`

      if [[ $LAST_LOGIN != "" ]]; then
        LAST_LOGIN=`echo "$LAST_LOGIN" | sed -e "s/Last login //" | sed -e "s/ on.*//"`

        PROCESSING_DATA=`echo "$LAST_LOGIN" | awk '{ if ($0 ~ /,/) {print $0}}'`

        if [[ $PROCESSING_DATA != "" ]]; then
          # Found the last login year
          LAST_LOGIN_YEAR=`echo "$LAST_LOGIN" | awk '{print $4}' | tr -d '\n'`
          LAST_LOGIN_MONTH=`echo "$LAST_LOGIN" | awk '{print $2}' | tr -d '\n'`

          LAST_LOGIN_DAY=`echo "$LAST_LOGIN" | awk '{ if($3 ~ /,/){outString=substr($3, 0, length($3)-1);print outString;}else{print $3}}' | tr -d '\n'`
          LAST_LOGIN_TIME=""
	    else
		if [ $UOS = 'SUNOS' ]; then
		    LAST_LOGIN_YEAR=`date +%Y`
		    LAST_LOGIN_MONTH=`echo "$LAST_LOGIN" | awk '{print $2}' | tr -d '\n'`

                    lastLoginMonth=""
                    curLoginMonth=""

                    AGet MNames "$LAST_LOGIN_MONTH"                
                    if  [[ $? -ne 0 ]]; then
                        AGet MNames "$LAST_LOGIN_MONTH" lastLoginMonth
                    fi

                    AGet MNames "$CURRENT_MONTH"                
                    if  [[ $? -ne 0 ]]; then
                        AGet MNames "$CURRENT_MONTH" curLoginMonth
                    fi

                    if [[ $lastLoginMonth != "" && $curLoginMonth != "" ]]; then
                        if [[ $lastLoginMonth -lt 7 && $curLoginMonth -gt 6 ]]; then
                            ((LAST_LOGIN_YEAR -= 1))
                        fi
                    fi

		    LAST_LOGIN_DAY=`echo "$LAST_LOGIN" | awk '{print $3}' | tr -d '\n'`
		    LAST_LOGIN_TIME=`echo "$LAST_LOGIN" | awk '{print $4}' | tr -d '\n'`
		else
		    LAST_LOGIN_YEAR=`date +%Y`
		    LAST_LOGIN_MONTH=`echo "$LAST_LOGIN" | awk '{print $1}' | tr -d '\n'`

                    lastLoginMonth=""
                    curLoginMonth=""

                    AGet MNames "$LAST_LOGIN_MONTH"                
                    if  [[ $? -ne 0 ]]; then
                        AGet MNames "$LAST_LOGIN_MONTH" lastLoginMonth
                    fi

                    AGet MNames "$CURRENT_MONTH"                
                    if  [[ $? -ne 0 ]]; then
                        AGet MNames "$CURRENT_MONTH" curLoginMonth
                    fi

                    if [[ $lastLoginMonth != "" && $curLoginMonth != "" ]]; then
                        if [[ $lastLoginMonth -lt 7 && $curLoginMonth -gt 6 ]]; then
                            ((LAST_LOGIN_YEAR -= 1))
                        fi
          fi

		    LAST_LOGIN_DAY=`echo "$LAST_LOGIN" | awk '{print $2}' | tr -d '\n'`
		    LAST_LOGIN_TIME=`echo "$LAST_LOGIN" | awk '{print $3}' | tr -d '\n'`
		fi
	    fi

        LAST_LODIN_DATE=$LAST_LOGIN_DAY" "$LAST_LOGIN_MONTH" "$LAST_LOGIN_YEAR
      fi
    fi

  echo $LAST_LODIN_DATE
}

function report
{
  typeset HOSTNAME=$HOST
  if [[ $ENABLEFQDN -eq 1 && $FQDN -eq 1 ]]; then
    HOSTNAME=$LONG_HOST_NAME
  fi

  #V4.4 Code to check SSH public key authentation status for users having password "*" in passwd file
  if [[ $OS = "SunOS" ]]; then
    SSHD_CONFIG="/etc/ssh/sshd_config"
    if [ -e "/usr/local/etc/sshd_config" ]; then
      SSHD_CONFIG="/usr/local/etc/sshd_config"
    fi
    AUTHKEYSFILE=`grep AuthorizedKeysFile $SSHD_CONFIG | grep -v "\#" | nawk {'print $2'}`
    PUBKEYAUTH=`grep PubkeyAuthentication $SSHD_CONFIG | grep -v "\#" | nawk {'print $2'}`
  else
    AUTHKEYSFILE=`grep AuthorizedKeysFile /etc/ssh/sshd_config | grep -v "\#" | awk {'print $2'}`
    PUBKEYAUTH=`grep PubkeyAuthentication /etc/ssh/sshd_config | grep -v "\#" | awk {'print $2'}`
  fi

  if [[ $AUTHKEYSFILE = "" ]]; then
    AUTHKEYSFILE=".ssh/authorized_keys"
  fi
  logDebug "Authorized_keys file path:$AUTHKEYSFILE and SSH public key auth enabled is $PUBKEYAUTH "

  if [[ $PROCESSNIS -eq 1 ]]; then
    FPASSWDFILE=$NISPASSWD
  fi

  if [[ $PROCESSLDAP -eq 1 ]]; then
    FPASSWDFILE=$LDAPPASSWD
	fi

  if [[ $PROCESSNIS -eq 0 && $PROCESSLDAP -eq 0 ]]; then
    FPASSWDFILE=$PASSWDFILE
  fi

  if [[ $IS_ADMIN_ENT_ACC -eq 1 && $NIS -eq 0 && $LDAP -eq 0  && $NOAUTOLDAP -eq 0 ]]; then
    if [[ $OS = "Linux" ]]; then
      `getent passwd > $ADMENTPASSWD`
      FPASSWDFILE=$ADMENTPASSWD
      elif [[ $OS = "SunOS" ]]; then
        `getent passwd > $ADMENTPASSWD`
        FPASSWDFILE=$ADMENTPASSWD
      fi
    fi

  DATA=`cat $FPASSWDFILE> $TMPFILE`

  while IFS=: read -r userid passwd uid gid gecos home shell
    do
      logDebug "report->read userid=$userid passwd=$passwd uid=$uid gid=$gid gecos=$gecos home=$home shell=$shell"

      matched=`echo $userid|grep ^+|wc -l`
      if [[ $matched -gt 0 ]]; then
        continue
      fi
      
      gecos=`Remove_Labeling_Delimiter "$gecos"`
      
      privilege=""
      pgroup=""
      userstate="Enabled"
      userllogon=""
      privField=""
      groupField=""
      privGroup=""
      userllogon=""
      
      if [[ $DLLD -eq 0 ]]; then
        userllogon=`Get_Last_Logon_User_Id "$userid"`
      fi

      if [[ $OS = "Linux" ]]; then
        if [[ $gid -lt 100 ]]; then
          logDebug "Found privileged ID: $userid"
          AGet groupGIDName ${gid} privField
        fi
      else
        matched=`echo $userid|egrep $PRIVUSERS|wc -l`
        if [[ $matched -gt 0 ]]; then
            tmpPrivGroup=""
            AGet groupGIDName ${gid} tmpPrivGroup
            matched=`echo $tmpPrivGroup|egrep $PRIVGROUPS|wc -l`
            if [[ $matched -gt 0 ]]; then
              logDebug "Found privileged ID: $userid"
              privField=$tmpPrivGroup
            fi
        fi
      fi

      AGet sudoUsers $userid testvar
      if  [[ $? -ne 0 ]]; then
        if [[ $privField != "" ]]; then
          privField="$privField,SUDO_$userid"
        else
          privField="SUDO_$userid"
        fi
        ADelete sudoUsers $userid
        logDebug "SUDOERS: deleting sudoUser array entry: $userid"
      fi

      AGet privUserGroups $userid testvar
      if  [[ $? -ne 0 ]]; then
        privGroup="GRP($testvar)"
        if [[ $privField != "" ]]; then
          privField=$privField",$privGroup"
        else
          privField=$privGroup
        fi
      fi

      AGet sudoUserGroups $userid testvar
      if  [[ $? -ne 0 ]]; then
        sudoGroup="SUDO_GRP($testvar)"
        if [[ $privField != "" ]]; then
          privField=$privField",$sudoGroup"
        else
          privField=$sudoGroup
        fi
      fi

      if  [[ $SUDOALL -ne 0 ]]; then
        if [[ $privField != "" ]]; then
          privField=$privField",SUDO_ALL"
        else
          privField="SUDO_ALL"
        fi
      fi

      AGet UserAliasList $userid testvar
      if  [[ $? -ne 0 ]]; then
        if [[ $privField != "" ]]; then
          privField="$privField,SUDO_$userid($testvar)"
        else
          privField="SUDO_$userid($testvar)"
        fi
        ADelete UserAliasList $userid
      fi

      AGet AllUserGroups $userid groupField

      if [[ $OS = "HP-UX" ]]; then
        userstate=`hpux_get_state $userid $OS`
        #echo "____> hpux_get_state:$userstate"
      else
        if [[ $SEC_READABLE -eq 1 ]]; then
          userstate=`get_state $userid $OS`
          #echo "____> get_state:$userstate"
        else
          #userstate="0"
          userstate="Enabled"
        fi
      fi

      # V2.6 iwong
      if [[ $TCB_READABLE -eq 0 ]]; then
        if [[ $passwd = "*" ]]; then
          if [[ $PUBKEYAUTH = "yes" ]]; then          #v4.4 Code to check SSH public key authentation status for users having password "*" in passwd file
            logDebug "Checking SSH public key file $home/$AUTHKEYSFILE for user $userid"
            if [[ -s $home/$AUTHKEYSFILE ]]; then
              userstate="SSH-Enabled"
              logDebug "SSH Key file:$home/$AUTHKEYSFILE is found for $userid"
            else
              #echo "User is disabled"
              userstate="Disabled"
            fi
          else
            userstate="Disabled"
            logDebug "User disabled $userid: passwd:$passwd"
          fi
        fi
      else
        logDebug "Bypassing * passwd check: $userid"
      fi
      # V2.6 iwong
      if [[ $shell = "/bin/false" ]]; then
        logDebug "DISABLED $userid: shell:$shell"
        userstate="Disabled"
      fi
      if [[ $shell = "/usr/bin/false" ]]; then
        logDebug "DISABLED $userid: shell:$shell"
        userstate="Disabled"
      fi

      scmstate=""
      if [[ $userstate = "Enabled" ]]; then
        scmstate="0"
      fi
      if [[ $userstate = "Disabled" ]]; then
        scmstate="1"
      fi

      if [[ $PROCESSNIS -eq 1 ]]; then
        userid="NIS/"$userid
      fi

      if [[ $PROCESSLDAP -eq 1 ]]; then
        userid="LDAP/"$userid
      fi

      #echo "userstate=$userstate"
      #SCM9 hostname<tab>os<tab>auditdate<tab>account<tab>userIDconv<tab>state<tab>l_logon<tab>group<tab>privilege

      if [[ $SCMFORMAT -eq 1 ]]; then
        print -r "$HOSTNAME\t$OS\t$myAUDITDATE\t$userid\t$gecos\t$scmstate\t$userllogon\t$groupField\t$privField" >> $OUTPUTFILE
        elif [[ $MEF2FORMAT -eq 1 ]]; then
          #MEF2 customer|system|account|userID convention data|group|state|l_logon|privilege
          print -r "$CUSTOMER|$HOSTNAME|$userid|$gecos|$groupField|$userstate|$userllogon|$privField" >> $OUTPUTFILE
        else
          #MEF3 “customer|identifier type|server identifier/application identifier|OS name/Application name|account|UICMode|userID convention data|state|l_logon |group|privilege”
          print -r "$CUSTOMER|S|$HOSTNAME|$OS|$userid||$gecos|$userstate|$userllogon|$groupField|$privField" >> $OUTPUTFILE
      fi

        #hostname<tab>os<tab>auditdate<tab>account<tab>userIDconv<tab>state<tab>l_logon<tab>group<tab>privilege
          #print "$HOST\t$OS\t$myAUDITDATE\t$userid\t$userCC/$userstatus/$userserial/$usercust/$usercomment\t$userstate\t$userllogon\t$pgroup\t$privilege"  >> $OUTPUTFILE

  done < $TMPFILE
  `rm -f $ADMENTPASSWD`
}

function Parse_LDAP_Netuser
{
  ################## Processing LDAP Ids #################
  if [[ $LDAP -eq 1 ]]; then
    IFS=" "
    attr=`$LDAPCMD -LLL -h $LDAPSVR -p $LDAPPORT -b $LDAPBASE uid=$1 uid userPassword uidNumber gidNumber loginShell gecos`
    if [[ $? -ne 0 ]]; then
      logAbort "unable access LDAP server"
    fi
    userid=$(echo "$attr" | sed -n 's/^uid: \(.*\)/\1/p')
    uid=$(echo "$attr" | sed -n 's/^uidNumber: \(.*\)/\1/p')
    gid=$(echo "$attr" | sed -n 's/^gidNumber: \(.*\)/\1/p')
    passwd=$(echo "$attr" | sed -n 's/^userPassword:: \(.*\)/\1/p')
    shell=$(echo "$attr" | sed -n 's/^loginShell: \(.*\)/\1/p')
    gecos=$(echo "$attr" | sed -n 's/^gecos: \(.*\)/\1/p')

    echo "$userid:$passwd:$uid:$gid:$gecos:$shell" >> $LDAPPASSWD

    logDebug "Parse_LDAP_Netuser attr is $attr "
    logDebug "Parse_LDAP_Netuser LDAP ID: $userid:$uid:$gid:$gecos:$shell:$passwd"
  fi
}

function Parse_LDAP_Netgrp
{
  if [[ $LDAP -eq 1 ]]; then
    netgrp=`echo $1 | tr -d '+' | tr -d '@' `
    logDebug "Netgroup is $netgrp "

    attr=`$LDAPCMD -LLL -h $LDAPSVR -p $LDAPPORT -b $LDAPBASE cn=$netgrp cn nisNetgroupTriple`
    logDebug "Parse_LDAP_Netgrp attr is $attr"
    if echo "$attr" | grep -i "nisNetgroupTriple:" > /dev/null; then
      ldapmem=$(echo "$attr" | sed -n 's/^nisNetgroupTriple:.*,\(.*\),.*/\1/p' | tr ['\n'] [,] )
    fi

    logDebug "Parse_LDAP_Netgrp Netgroup $netgrp:$ldapmem"

    IFS=,;for nextuser in ${ldapmem}
      do
        logDebug "Parse_LDAP_Netgrp $nextuser is processing "

        AGet PasswdUser "${nextuser}" testvar
        if [[ $? -eq 0 ]]; then
          Parse_LDAP_Netuser $nextuser
        else
          logDebug "Parse_LDAP_Netgrp User $nextuser Already exist"
          AGet Netgrplist ${netgrp} testvar
          if  [[ $? -eq 0 ]]; then
            AStore Netgrplist ${netgrp} "$nextuser"
          else
            AStore Netgrplist ${netgrp} ",$nextuser" append
          fi
          continue
        fi

        AGet Netgrplist ${netgrp} testvar
        if  [[ $? -eq 0 ]]; then
          AStore Netgrplist ${netgrp} "$userid"
        else
          AStore Netgrplist ${netgrp} ",$userid" append
        fi

        AStore PasswdUser ${userid} "$userid"
        AGet primaryGroupUsers ${gid} testvar
        if  [[ $? -eq 0 ]]; then
          AStore primaryGroupUsers ${gid} "$userid"
        else
          AStore primaryGroupUsers ${gid} ",$userid" append
        fi
        AGet primaryGroupUsers ${gid} testvar
      done
    IFS=" "
  fi
}

function IsAdminEntAccessible
{
  if [[ $OS = "AIX" ]]; then
    ret=`lsuser -R LDAP ALL  2>/dev/null`
    if [[ $? -eq 0 ]]; 
    then
      logInfo "Server $HOST ($uname) is LDAP connected"
      IS_ADMIN_ENT_ACC=1
    else
      logInfo "Server $HOST ($uname) is not LDAP connected"
    fi  
  elif [[ $OS = "Linux" ]]; then
      if [[ x"`getent passwd`" = x ]]; then
      logInfo "Server $HOST ($uname) is not support getent utility"   
    else
      IS_ADMIN_ENT_ACC=1    
    fi
  elif [[ $OS = "SunOS" ]]; then
    if [[ x"`getent passwd`" = x ]]; then
      logInfo "Server $HOST ($uname) is not support getent utility"   
    else
      IS_ADMIN_ENT_ACC=1    
    fi
  else
    logInfo "Operating system: $uname not supported for checks of LDAP!"
  fi
  logDebug "IsAdminEntAccessible IS_ADMIN_ENT_ACC=$IS_ADMIN_ENT_ACC"
  return 0
}

function check_pam
{
  conffile="/etc/ldap.conf";
  
  if [ -a $conffile ]; then
    while read line; do 
      if echo "$line" | grep -i "^pam_check_host_attr" > /dev/null; then
        val=$(echo "$line" | sed -n 's/^pam_check_host_attr \(.*\)/\1/p')
        if [[ $val = "yes" ]]; then
          logDebug "pam_check_host_attr yes"
          return 1;
        fi   
      fi
    done < $conffile
  fi
  logDebug "pam_check_host_attr no"
  return 0
}


function process_LDAP_users
{
  IsPAM=0
  check_pam
  if  [[ $? -eq 1 ]]; then
    IsPAM=1
  fi

  DATA=`$LDAPCMD -LLL -h $LDAPSVR -b $LDAPBASE -p $LDAPPORT uid=* uid userpassword uidNumber gidNumber loginShell gecos host >> /tmp/ldap_users`;
  if [[ $? -ne 0 ]]; then
    logAbort "unable access LDAP server"
  fi

  firsttime='true'
  userid=''
  passwd=''
  uid=''
  gid=''
  gecos=''
  shell=''
  checkHost=0
  
  while read line; do
    logDebug "process_LDAP_users->read line=$line"

    if echo "$line" | grep -i "uidNumber:" > /dev/null; then
      uid=$(echo "$line" | sed -n 's/^uidNumber: \(.*\)/\1/p')
    fi

    if echo "$line" | grep -i "gidNumber:" > /dev/null; then
      gid=$(echo "$line" | sed -n 's/^gidNumber: \(.*\)/\1/p')
    fi

    if echo "$line" | grep -i "userPassword::" > /dev/null; then
      passwd=$(echo "$line" | sed -n 's/^userPassword:: \(.*\)/\1/p')
    fi

    if echo "$line" | grep -i "loginShell:" > /dev/null; then
      shell=$(echo "$line" | sed -n 's/^loginShell: \(.*\)/\1/p')
    fi

    if echo "$line" | grep -i "gecos:" > /dev/null; then
      gecos=$(echo "$line" | sed -n 's/^gecos: \(.*\)/\1/p')
    fi

    if echo "$line" | grep -i "host:" > /dev/null; then
      host=$(echo "$line" | sed -n 's/^host: \(.*\)/\1/p')
      if [[ $IsPAM -eq 1 && ($host = $HOST || $host = $LONG_HOST_NAME) ]]; then
        checkHost=1
        logDebug "process_LDAP_users userhost=$host"
      fi  
    fi
    
    if echo "$line" | grep -i "dn: uid=" > /dev/null; then
      if [[ $firsttime = 'true' ]]; then
        userid=$(echo $line | sed -e 's/^\(dn: uid=\)//' | sed -e 's/,.*//')
        firsttime='false'
        continue
      fi
      if [[ $OS = "AIX" ]]; then
        testvar=0
        AGet LDAP_users ${userid} testvar
        if [[ $testvar -eq 2 ]]; then
          echo "$userid:$passwd:$uid:$gid:$gecos::$shell" >> $LDAPPASSWD
        else
          logDebug "process_LDAP_users: skip user $userid"
        fi  
      else  
        if [[ $IsPAM -eq 1 ]]; then
          if [[ $checkHost -eq 1 ]]; then 
        echo "$userid:$passwd:$uid:$gid:$gecos::$shell" >> $LDAPPASSWD
          else
            logDebug "process_LDAP_users: skip user $userid"
          fi  
        else
          echo "$userid:$passwd:$uid:$gid:$gecos::$shell" >> $LDAPPASSWD          
        fi  
          checkHost=0
      fi
        
      logDebug "process_LDAP_users->processed userid=$userid passwd=$passwd uid=$uid gid=$gid gecos=$gecos shell=$shell"

      passwd=""
      uid=""
      gid=""
      gecos=""
      shell=""
      userid=$(echo $line | sed -e 's/^\(dn: uid=\)//' | sed -e 's/,.*//')
    fi
    done < /tmp/ldap_users

  if [ -n $userid ]; then
    if [[ $OS = "AIX" ]]; then
      testvar=0
      AGet LDAP_users ${userid} testvar
      if [[ $testvar -eq 2 ]]; then
        echo "$userid:$passwd:$uid:$gid:$gecos::$shell" >> $LDAPPASSWD
      else
        logDebug "process_LDAP_users: skip user $userid"
      fi  
    else  
      if [[ $IsPAM -eq 1 ]]; then
        if [[ $checkHost -eq 1 ]]; then 
      echo "$userid:$passwd:$uid:$gid:$gecos::$shell" >> $LDAPPASSWD
        else
          logDebug "process_LDAP_users: skip user $userid"
        fi  
      else
        echo "$userid:$passwd:$uid:$gid:$gecos::$shell" >> $LDAPPASSWD          
      fi  
    fi
  fi

  if [ -a /tmp/ldap_users ]; then
    rm /tmp/ldap_users
  fi
}

function findSudoersFile
{
  SUDOERFILE="/dev/null"
  SUDOERFILE1="/etc/sudoers"
  SUDOERFILE2="/opt/sfw/etc/sudoers"
  SUDOERFILE3="/usr/local/etc/sudoers"
  SUDOERFILE4="/opt/sudo/etc/sudoers"
  SUDOERFILE5="/opt/sudo/etc/sudoers/sudoers"
  SUDOERFILE6="/usr/local/etc/sudoers/sudoers"
  SUDOERFILE7="/opt/sudo/sudoers"

  if [ -r $SUDOERFILE1 ]; then
    SUDOERFILE=$SUDOERFILE1
  elif [ -r $SUDOERFILE2 ]; then
    SUDOERFILE=$SUDOERFILE2
  elif [ -r $SUDOERFILE3 ]; then
    SUDOERFILE=$SUDOERFILE3
  elif [ -r $SUDOERFILE4 ]; then
    SUDOERFILE=$SUDOERFILE4
  elif [ -r $SUDOERFILE5 ]; then
    SUDOERFILE=$SUDOERFILE5
  elif [ -r $SUDOERFILE6 ]; then
    SUDOERFILE=$SUDOERFILE6
  elif [ -r $SUDOERFILE7 ]; then
    SUDOERFILE=$SUDOERFILE7
  fi
}

function check_nisplus
{
  if [ -s "/var/nis/NIS_COLD_START" ]; then
   return 1
  fi
  return 0;  
}

ClearFile()
{
    typeset FILE=$1
    
    `echo "" > $FILE && rm $FILE` 
    if [[ $? -ne 0 ]]; then
      logMsg "ERROR" "Unable to open $FILE"
    fi
}


function Mef_Users_Post_Process
{
    typeset outputFile=$1 ibmOnly=$2 customerOnly=$3
    
    isIbmUser=0
    returnCode=0
    
    if [[ $ibmOnly -eq 1 && $customerOnly -eq 1 ]]; then
        return 1
    fi
    
    if [[ $ibmOnly -eq 0 && $customerOnly -eq 0 ]]; then
        return 1
    fi
    
    baseMefName=`basename "$outputFile"`
    tmpOut="/tmp/${baseMefName}_tmp"
    
    if [[ -f "$outputFile" ]]; then
        # Storing file's data
        `echo "" >> "$outputFile"`
        `cat "$outputFile" | sed 's/[\x0D\x0A]*$//' > "$tmpOut"`
        `echo "" >> "$tmpOut"`
        
        # Clear the output file
        `ClearFile "$outputFile"`
        
        while read nextline; do
            if [[ $nextline != "" ]]; then
                isIbmUser=0
                
                CUSTOMER_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[1];
                            }
                        '`
                        
                HOST_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[3];
                            }
                        '`
                        
                INSTANCE_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[4];
                            }
                        '`
                        
                USER_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[5];
                            }
                        '`
                        
                FLAG_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[6];
                            }
                        '`
                        
                DESCRIPTION_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[7];
                            }
                        '`
                        
                USERSTATE_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[8];
                            }
                        '`
                        
                USERLLOGON_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[9];
                            }
                        '`
                        
                GROUPS_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[10];
                            }
                        '`
                        
                ROLES_MEF3=`echo "$nextline" | awk '
                            {
                                split($0, str, "|");
                                print str[11];
                            }
                        '`
                
                # 1. Checking on the signature record
                matched=`echo "$nextline" | egrep "NOTaRealID" | wc -l`
                if [[ $matched -gt 0 ]]; then
                    `echo "$nextline" >> $outputFile`
                    continue
                fi
                
                # 2. Checking if user has this format <login name>@<location>.ibm.com
                SPECIAL_FLAG=`echo $USER_MEF3 | grep -i '.*@.*\.ibm\.com'`                
                if [[ $SPECIAL_FLAG != "" && $ibmOnly -ne 0 ]]; then
                    `echo "$nextline" >> $outputFile`
                    continue
                fi
                
                if [[ $SPECIAL_FLAG != "" && $customerOnly -ne 0 ]]; then
                    continue
                fi
                
                matched=`echo "$DESCRIPTION_MEF3" | grep ".\{3\}\/[^\/]*\/[^\/]*\/[^\/]*\/.*" | wc -l`
                if [[ $matched -eq 0 ]]; then
                    # description of the current userID doesn't contain URT format information in the description field
                    USERGECOS_MEF3=`GetURTFormat "$DESCRIPTION_MEF3"`
                else
                    USERGECOS_MEF3=$DESCRIPTION_MEF3
                fi
                
                matched=`echo "$USERGECOS_MEF3" | grep ".\{3\}\/[^\/]*\/[^\/]*\/[^\/]*\/.*" | wc -l`
                if [[ $matched -ne 0 ]]; then
                    matched=`echo "$USERGECOS_MEF3" | grep ".\{3\}\/[ISFTEN]\/[^\/]*\/[^\/]*\/.*" | wc -l`
                    if [[ $matched -ne 0 ]]; then
                        isIbmUser=1
                    fi
                else
                    returnCode=3
                fi
                
                if [[ $isIbmUser -eq 1 && $ibmOnly -eq 1 ]]; then
                    `echo "$nextline" >> "$outputFile"`
                    continue
                fi
                
                if [[ $isIbmUser -eq 0 && $customerOnly -eq 1 ]]; then
                    `echo "$nextline" >> "$outputFile"`
                    continue
                fi
            fi
        done < "$tmpOut"
    else
        return 2
    fi
    
    `ClearFile "$tmpOut"`
    logInfo "Finished .MEF3 report filtering"  
    return $returnCode
}

function Filter_mef3
 {
  logInfo "Started .MEF3 report filtering"
  logDebug "filter: OutputFile:$OUTPUTFILE"
  logDebug "filter: ibmOnly:$IBMONLY"
  logDebug "filter: customerOnly:$CUSTOMERONLY"

  if [[ $ibmonly != 0 || $customeronly != 0 ]]; then
      Mef_Users_Post_Process $OUTPUTFILE $IBMONLY $CUSTOMERONLY
  fi
}

function collect_LDAP_users_aix
{
  if [[ $OS = "AIX" ]]; then
    while read nextline; do
      nextline=${nextline%%\**}
      
    if echo "$nextline" | grep -i ":" > /dev/null; then
      temp_user=${nextline%%:}
      testvar=0
      AStore LDAP_users ${temp_user} "$testvar"
      logDebug "Filter LDAP: username = $temp_user"
      continue
    fi      
    
    if echo "$nextline" | grep -i "SYSTEM = \"LDAP\"" > /dev/null; then
      AGet LDAP_users ${temp_user} testvar
        let testvar=testvar+1
        AStore LDAP_users ${temp_user} "$testvar"
        logDebug "Filter LDAP: username = $username SYSTEM"  
      continue
    fi  

    if echo "$nextline" | grep -i "registry = LDAP" > /dev/null; then
      AGet LDAP_users ${temp_user} testvar
        let testvar=testvar+1
        AStore LDAP_users ${temp_user} "$testvar"
        logDebug "Filter LDAP: username = $username registry"  
      continue
    fi
    
    done < $SECUSER
  fi  
}
#####################################################################################################
## MAIN
#####################################################################################################
AInit CC '559' 'TT' '603' 'AL' '612' 'DZ' '613' 'AR' '615' 'BD' '616' 'AU' '618' 'AT' '619' 'BS' '620' 'BH' '621' 'BB' '624' 'BE' '627' 'BM' '629' 'BO' '631' 'BR' '636' 'BW' '644' 'BG' '649' 'CA' '650' 'CM' '652' 'LK' '655' 'CL' '656' 'GA' '661' 'CO' '663' 'CR' '659' 'CR' '666' 'CY' '668' 'CZ' '672' 'CN' '677' 'AE' '678' 'DK' '681' 'DO' '683' 'EC' '693' 'SK' '694' 'KZ' '699' 'BA' '702' 'FI' '704' 'HR' '705' '00' '706' 'FR' '707' 'YU' '708' 'SL' '724' 'DE' '726' 'GR' '731' 'GT' '735' 'HN' '738' 'HK' '740' 'HU' '744' 'IN' 'IN1' 'IN' '749' 'ID' '754' 'IE' '756' 'IL' '757' 'CI' '758' 'IT' '759' 'JM' '760' 'JP' 'JP3' 'JP' '762' 'JO' '766' 'KR' '767' 'KW' '768' 'LB' '778' 'MY' '781' 'MX' '784' 'MA' '788' 'NL' '791' 'AN' '796' 'NZ' '798' 'LA' '799' 'NI' '805' 'OM' '806' 'NO' '808' 'PK' '811' 'PA' '813' 'PY' '815' 'PE' '818' 'PH' '820' 'PL' '821' 'RU' '822' 'PT' '823' 'QA' '824' 'SN' '825' 'ZW' '826' 'RO' '829' 'SV' '832' 'SA' '834' 'SG' '838' 'ES' '840' 'TN' '843' 'SR' '846' 'SE' '848' 'CH' '852' 'VN' '856' 'TH' '858' 'TW' '862' 'TR' '864' 'ZA' '865' 'EG' '866' 'GB' '869' 'UY' '871' 'VE' '877' 'FX' '889' 'UA' '897' 'US' 'CA2' 'CP' 'CA3' 'CP' 'CA4' 'CP' 'CA6' 'CP' 'CA7' 'CP' 'US5' 'US'

PERL=`which perl`
SCRIPTNAME=$0
CKSUM=`cksum $SCRIPTNAME | awk '{ print $1 }'`

logHeader
 
date=`date +%d%b%Y`
date=`echo $date | tr -d ' '`
myAUDITDATE=`date +%Y-%m-%d-%H.%M.%S`
typeset -u DATE=$date
findSudoersFile
PASSWDFILE="/etc/passwd"
GROUPFILE="/etc/group"
LONG_HOST_NAME=`hostname`
HOST=${LONG_HOST_NAME%%.*}
ENABLEFQDN=1
TMPFILE="/tmp/urt_extract_global.tmp"       #4.2 Updated to keep tmpfile in /tmp
CUSTOMER="TML"
OUTPUTFILE="/tmp/$CUSTOMER""_""$DATE""_""$HOST.mef"
OS=`uname -a|cut -d" " -f1`
USERCC="897"

uname=`uname`
export uname

if [ -f /bin/sudo ]; then
  SUDOCMD="/bin/sudo"
  SUDOVER=`$SUDOCMD -V|grep -i version|cut -f3 -d" "`
  logInfo "SUDO Version: $SUDOVER"
elif [ -f /usr/bin/sudo ]; then
  SUDOCMD="/usr/bin/sudo"
  SUDOVER=`$SUDOCMD -V|grep -i version|cut -f3 -d" "`
  logInfo "SUDO Version: $SUDOVER"
elif [ -f /usr/local/bin/sudo ]; then
  SUDOCMD="/usr/local/bin/sudo"
  SUDOVER=`$SUDOCMD -V|grep -i version|cut -f3 -d" "`
  logInfo "SUDO Version: $SUDOVER"
elif [ -f /usr/local/sbin/sudo ]; then
  SUDOCMD="/usr/local/sbin/sudo"
  SUDOVER=`$SUDOCMD -V|grep -i version|cut -f3 -d" "`
  logInfo "SUDO Version: $SUDOVER"
else
  SUDOVER="NotAvailable"
  logMsg "WARNING" "unable to get Sudo Version:$SUDOVER."
  EXIT_CODE=1
fi

if [[ $OS = "AIX" ]]; then
  SECUSER="/etc/security/user"
  SPASSWD="/etc/security/passwd"
elif [[ $OS = "HP-UX" ]]; then
  SECUSER=""
  SPASSWD="/etc/shadow"
elif [[ $OS = "SunOS" ]]; then
  SECUSER=""
  SPASSWD="/etc/shadow"
elif [[ $OS = "Linux" ]]; then
  SECUSER=""
  SPASSWD="/etc/shadow"
elif [[ $OS = "Tru64" ]]; then
  SECUSER=""
  SPASSWD="/etc/shadow"
else
  SECUSER=""
  SPASSWD="/etc/shadow"
fi

SCMFORMAT="0"
MEF2FORMAT="0"
NEWOUTPUTFILE=""
NIS=0
LDAP=0
ldap_tmp="/tmp/urt_temp"
ldap_tmp1="/tmp/urt_temp1"
NOAUTOLDAP=0
CUSTOMERONLY=0
IBMONLY=0
OWNER=""
DLLD=0

IS_ADMIN_ENT_ACC=0

while getopts ":f:g:p:r:c:o:O:s:u:m:C:dSMP:n:L:NqhaKID" opt; do
  case $opt in
  f ) 
    #echo "-f $OPTARG"
    SUDOERFILE="$OPTARG"
    KNOWPAR=$(echo "$KNOWPAR -f")
    ;;
  g ) 
    #echo "-g $OPTARG"
    GROUPFILE="$OPTARG"
    NOAUTOLDAP=1
    KNOWPAR=$(echo "$KNOWPAR -g")
    ;;
  p ) 
    #echo "-p $OPTARG"
    PASSWDFILE="$OPTARG"
    NOAUTOLDAP=1
    KNOWPAR=$(echo "$KNOWPAR -p")
    ;;
  r ) 
    #echo "-r $OPTARG"
    NEWOUTPUTFILE="$OPTARG"
    KNOWPAR=$(echo "$KNOWPAR -r")
    ;;
  c ) 
    #echo "-c $OPTARG"
    CUSTOMER="$OPTARG"
    KNOWPAR=$(echo "$KNOWPAR -c")
    ;;
  o ) 
    #echo "-o $OPTARG"
    OS="$OPTARG"
    KNOWPAR=$(echo "$KNOWPAR -o")
    ;;
  s ) 
    #echo "-o $OPTARG"
    SPASSWD="$OPTARG"
    KNOWPAR=$(echo "$KNOWPAR -s")
    ;;
  u ) 
    #echo "-o $OPTARG"
    SECUSER="$OPTARG"
    KNOWPAR=$(echo "$KNOWPAR -u")
    ;;
  m ) 
    #echo "-o $OPTARG"
    HOST="$OPTARG"
    LONG_HOST_NAME=$HOST
    ENABLEFQDN=0
    KNOWPAR=$(echo "$KNOWPAR -m")
    ;;
  d ) 
    #echo "-o $OPTARG"
    DEBUG="1"
    KNOWPAR=$(echo "$KNOWPAR -d")
    ;;
  S ) 
    SCMFORMAT="1"
    KNOWPAR=$(echo "$KNOWPAR -S")
    ;;
  M ) 
    MEF2FORMAT="1"
    KNOWPAR=$(echo "$KNOWPAR -M")
    ;;
  P ) 
    #echo "-p $OPTARG"
    PRIVFILE="$OPTARG"
    KNOWPAR=$(echo "$KNOWPAR -p")
    ;;
  n )                     #4.3 Custom Signature
    #echo "-n $OPTARG"
    SIG=`echo $OPTARG | tr "[:lower:]" "[:upper:]"`
    KNOWPAR=$(echo "$KNOWPAR -n")
    ;;
   N )                      #4.5 Added NIS and LDAP 
    #echo "-n $OPTARG"
    NIS=1
    KNOWPAR=$(echo "$KNOWPAR -N")
    ;;
  L )
    LDAP=1
    if echo "$OPTARG" | grep  "\:" >/dev/null; then
    LDAPARG="$OPTARG"
    LDAPSVR=`echo $OPTARG | awk -F: '{ print $1 }'`
    LDAPPORT=`echo $OPTARG | awk -F: '{ print $2 }'`
    LDAPBASE=`echo $OPTARG | awk -F: '{ print $3 }'`
    else
     logAbort "-L ServerName/IP:port:BaseDN\neg: urt_extract_ibm.ksh -L 127.0.0.1:389:DC=IBM,DC=COM"
    fi
    KNOWPAR=$(echo "$KNOWPAR -L")
    ;;
  K )                      #4.5 Added NIS and LDAP 
    CUSTOMERONLY=1
    KNOWPAR=$(echo "$KNOWPAR -K")
    ;;
  I )                      #4.5 Added NIS and LDAP 
    IBMONLY=1
    KNOWPAR=$(echo "$KNOWPAR -I")
    ;;
  h|help ) 
    echo
    echo "Version: $VERSION"
    echo "USAGE: urt_extract_global.ksh [-f sudoers_file] [-r results_file] [-p passwd_file]"
    echo "                           [-g group_file] [-c customer] [-m hostname]" 
    echo "                           [-o ostype] [-s shadowfile] -u [secuserfile]" 
    echo "                           [-S] [-M] [-P privfile] [-n TSCM|SCR|TCM|FUS]" 
    echo "                           [-L <LDAP SERVER IP:Port:BASE DN>]  [-N] [-q] [-a]" 
    echo "                           [-C <userCC>] [-K] [-I] [-O <owner>] [-D]" 
    echo
    echo "  -S   Change output file format to scm9, instead of mef3"
    echo "  -M   Change output file format to mef2, instead of mef3"
    echo "  -q   Use fully qualified domain name(FQDN)"
    echo "  -a   Fetch only local user IDs (Linux, Solaris)"
    echo "  -K   Flag to indicate if only Customer userID's should be written to the output"
    echo "  -I   Flag to indicate if only IBM userID's should be written to the output"
    echo
    echo " Defaults:"
    echo "     CUSTOMER: $CUSTOMER"
    echo "   SUDOERFILE: $SUDOERFILE"
    echo "   PASSWDFILE: $PASSWDFILE"
    echo "    GROUPFILE: $GROUPFILE"
    echo "  RESULTSFILE: $OUTPUTFILE"
    echo "   SHADOWFILE: $SPASSWD"
    echo "  SECUSERFILE: $SECUSER"
    echo "           OS: $OS(AIX|HP-UX|SunOS|Linux|Tru64"
    echo "     HOSTNAME: $HOST"
    echo "        CKSUM: $CKSUM"
    echo
    echo " Output is mef format including SUDO privilege data."
    echo " User 'state' (enabled/disabled) is extracted if possible."
    exit 9
    ;;
  q )                   
    FQDN=1
    KNOWPAR=$(echo "$KNOWPAR -q")
    ;;
  a )
    NOAUTOLDAP=1
    KNOWPAR=$(echo "$KNOWPAR -a")
    ;;
  O )                   
    OWNER="$OPTARG"
    KNOWPAR=$(echo "$KNOWPAR -O")
    ;;
  D )                   
    DLLD=1
    KNOWPAR=$(echo "$KNOWPAR -D")
    ;;
   * )
   UNKNOWPAR=$(echo "$UNKNOWPAR -$OPTARG")
   ;; 
  esac
done

if [[ $OS = "AIX" ]]; then
  logInfo "Found AIX"
  PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^lpd$|^imnadm$|^ipsec$|^ldap$|^lp$|^snapp$|^invscout$|^nobody$|^notes$'
  PRIVGROUPS='^system$|^security$|^bin$|^sys$|^adm$|^uucp$|^mail$|^printq$|^cron$|^audit$|^shutdown$|^ecs$|^imnadm$|^ipsec$|^ldap$|^lp$|^haemrm$|^snapp$|^hacmp$|^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$'
elif [[ $OS = "HP-UX" ]]; then
  logInfo "Found HP-UX"
  PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^lp$|^nuucp$|^hpdb$|^imnadm$|^nobody$|^notes$'
  PRIVGROUPS='^root$|^other$|^bin$|^sys$|^adm$|^daemon$|^mail$|^lp$|^tty$|^nuucp$|^nogroup$|^imnadm$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^notes$'
elif [[ $OS = "SunOS" || $OS = "Solaris" ]]; then
  logInfo "Found $OS"
  PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^imnadm$|^lp$|^smmsp$|^listen$'
  PRIVGROUPS='^system$|^security$|^bin$|^sys$|^uucp$|^mail$|^imnadm$|^lp$|^root$|^other$|^adm$|^tty$|^nuucp$|^daemon$|^sysadmin$|^smmsp$|^nobody$|^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$'
elif [[ $OS = "Linux" ]]; then
  logInfo "Found Linux"
  PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^nobody$|^notes$'
  PRIVGROUPS='^notes$|^mqm$|^dba$|^sapsys$|^db2iadm1$|^db2admin$|^sudo$|^wheel$'
elif [[ $OS = "Tru64" ]]; then
  logInfo "Found Tru64"
  PRIVUSERS='^adm$|^auth$|^bin$|^cron$|^daemon$|^inmadm$|^lp$|^nuucp$|^ris$|^root$|^sys$|^tcb$|^uucp$|^uucpa$|^wnn$'
  PRIVGROUPS='^adm$|^auth$|^backup$|^bin$|^cron$|^daemon$|^inmadm$|^kmem$|^lp$|^lpr$|^mail$|^mem$|^news$|^operator$|^opr$|^ris$|^sec$|^sysadmin$|^system$|^tape$|^tcb$|^terminal$|^tty$|^users$|^uucp$'
else
  logInfo "Found Unknown OS"
  PRIVUSERS='^root$|^daemon$|^bin$|^sys$|^adm$|^uucp$|^nuucp$|^lpd$|^imnadm$|^ipsec$|^ldap$|^lp$|^snapp$|^invscout$|^nobody$|^notes$'
  PRIVGROUPS='^1bmadmin$|^adm$|^audit$|^bin$|^cron$|^daemon$|^db2admin$|^db2iadm1$|^dba$|^ecs$|^hacmp$|^haemrm$|^ibmadmin$|^imnadm$|^ipsec$|^ldap$|^lp$|^mail$|^mqm$|^nobody$|^nogroup$|^notes$|^nuucp$|^other$|^printq$|^root$|^sapsys$|^security$|^shutdown$|^smmsp$|^snapp$|^suroot$|^sys$|^sysadm$|^system$|^tty$|^uucp$|^wheel$'
fi

if [[ $NEWOUTPUTFILE != "" ]]; then
  if echo "$NEWOUTPUTFILE" | grep "/" > /dev/null; then
    OUTPUTFILE=$NEWOUTPUTFILE
  else
    OUTPUTFILE="/tmp/$NEWOUTPUTFILE"
  fi
else
  if [[ $SCMFORMAT -eq 1 ]]; then
    OUTPUTFILE="/tmp/$CUSTOMER""_""$DATE""_""$HOST.scm9"
  elif [[ $MEF2FORMAT -eq 1 ]]; then
    OUTPUTFILE="/tmp/$CUSTOMER""_""$DATE""_""$HOST.mef"
  else
    OUTPUTFILE="/tmp/$CUSTOMER""_""$DATE""_""$HOST.mef3"
  fi
fi

if [[ $PRIVFILE != "" ]]; then
  if [ -r $PRIVFILE ]; then
    logDebug "Reading PRIVFILE: $PRIVFILE"
    while read line; do
      matched=`echo $line|egrep -v '^\s*$'|wc -l`
      if [[ $matched -gt 0 ]]; then
        logDebug "Found Additional Priv group: ----$line""----"
        PRIVGROUPS=$PRIVGROUPS"|^"$line'$'
      fi

    done < $PRIVFILE
  else
    logMsg "WARNING" "unable to read PRIVFILE:PRIVFILE."
    EXIT_CODE=1
  fi
fi

logDebug "PRIVSUSERS: $PRIVUSERS"
logDebug "PRIVSGROUPS: $PRIVGROUPS"

SEC_READABLE=1
if [ ! -r $SPASSWD ]; then
  logMsg "WARNING" "unable to read SPASSWD:$SPASSWD. Account state may be missing from extract"
  SEC_READABLE=0
  EXIT_CODE=1
fi

if [[ $OS = "AIX" ]]; then
  if [ ! -r $SECUSER ]; then
    logMsg "WARNING" "unable to read SECUSER:$SECUSER. Account state may be missing from extract"
    SEC_READABLE=0
    EXIT_CODE=1
  fi
fi

TCB_READABLE=0
if [[ $OS = "HP-UX" ]]; then
  #echo "CHECKING: /usr/lbin/getprpw."
  if [ ! -x /usr/lbin/getprpw ]; then
    logMsg "WARNING" "unable to execute /usr/lbin/getprpw. Account state may be missing from extract"
    TCB_READABLE=0
    EXIT_CODE=1
  else
    TCB_READABLE=1
  fi
fi

logDebug "TCB_READABLE: $TCB_READABLE"

if [ $SUDOERFILE = "/dev/null" ]; then
  logMsg "WARNING" "unable to find sudoers file.  Account SUDO privileges will be missing from extract"
  EXIT_CODE=1
elif [ ! -r $SUDOERFILE ]; then
  logMsg "WARNING" "unable to read SUDOERFILE:$SUDOERFILE file.  Account SUDO privileges will be missing from extract"
  EXIT_CODE=1
fi

if [ ! -r $GROUPFILE ]; then
logAbort "unable to read $GROUPFILE"
fi

if [ ! -r $PASSWDFILE ]; then
logAbort "unable to read $PASSWDFILE"
fi

`echo "" > $OUTPUTFILE&& rm $OUTPUTFILE` 
if [[ $? -ne 0 ]]; then
  logAbort "unable to open OUTPUTFILE:$OUTPUTFILE"
fi

`echo "" > $TMPFILE&& rm $TMPFILE` 
if [[ $? -ne 0 ]]; then
  logAbort "unable to open $TMPFILE"
fi

AStore MNames "Jul" "1"
AStore MNames "Aug" "2"
AStore MNames "Sep" "3"
AStore MNames "Oct" "4"
AStore MNames "Nov" "5"
AStore MNames "Dec" "6"
AStore MNames "Jan" "7"
AStore MNames "Feb" "8"
AStore MNames "Mar" "9"
AStore MNames "Apr" "10"
AStore MNames "May" "11"
AStore MNames "Jun" "12"

errorCount=0

# call the function for check on the possibility usages of system functions for extracts userIDs from services LDAP, NIS, NIS+
IsAdminEntAccessible
logInfo "Checking on the admin ent accessible => '$IS_ADMIN_ENT_ACC'"

ADMENTPASSWD="/tmp/adment_passwd"
ADMENTGROUP="/tmp/adment_group"

logPostHeader $0

PROCESSNIS=0
PROCESSLDAP=0

if [[ $NIS -eq 1 ]]; then
    NISPLUS=0
    check_nisplus
    if  [[ $? -eq 1 ]]; then
      NISPLUS=1
    fi
    logInfo "Start NIS processing"
    if [[ NISPLUS -eq 1 ]]; then
      ret=`niscat passwd.org_dir > /tmp/nis_passwd`
      ret=`niscat group.org_dir > /tmp/nis_group`
    else
      ret=`ypcat passwd > /tmp/nis_passwd`
      ret=`ypcat group > /tmp/nis_group`
    fi
    
    if [[ $? -ne 0 ]]; then
       logAbort "Unable to accessing NIS server"
    fi
    PROCESSNIS=1
    NISPASSWD="/tmp/nis_passwd"
    NISGROUP="/tmp/nis_group"
    logInfo "Parse NIS users"    
    Parse_User
    logInfo "Parse NIS groups"        
    Parse_Grp
    logInfo "Parse Sudo"    
    Parse_Sudo        # for NIS's accounts we must extract all data from SUDO-settings
    report
    rm -f /tmp/nis_passwd /tmp/nis_group
    
    #cleaning of hashes
    AUnset primaryGroupUsers
    AUnset PasswdUser
    AUnset groupGIDName
    AUnset ALLGroupUsers
    AUnset AllUserGroups
    AUnset privUserGroups
    AUnset Ullogon
    AUnset sudoUsers
    AUnset sudoGroups
    AUnset sudoUserGroups
    AUnset aliasUsers
    AUnset validHostAlias
    AUnset Netgrplist
    logInfo "Finish NIS processing"  
    PROCESSNIS=0  
fi

if [[ $LDAP -eq 1 ]]; then
    if [[ $OS = "AIX" || $OS = "SunOS" ]]; then
        LDAPCMD="ldapsearch"
    else
        LDAPCMD="ldapsearch -x"
    fi
fi

if [[ $IS_ADMIN_ENT_ACC -eq 1 && $NIS -eq 0 && $LDAP -eq 1 ]];
then
  checkforldappasswd
  if  [[ $? -eq 1 ]]; then
    logInfo "Start LDAP processing"
  
    LDAPPASSWD="/tmp/ldappasswd"
    LDAPGROUP="/tmp/ldapgroup"

    PROCESSLDAP=1
  
    logInfo "Parse LDAP users"
    collect_LDAP_users_aix
    process_LDAP_users
    parse_LDAP_grp
    Parse_User
    logInfo "Parse LDAP groups"     
    Parse_Grp
    logInfo "Parse Sudo"
    Parse_Sudo
    logInfo "Finish LDAP processing"
    report  
    AUnset primaryGroupUsers
    AUnset PasswdUser
    AUnset groupGIDName
    AUnset ALLGroupUsers
    AUnset AllUserGroups
    AUnset privUserGroups
    AUnset Ullogon
    AUnset sudoUsers
    AUnset sudoGroups
    AUnset sudoUserGroups
    AUnset aliasUsers
    AUnset validHostAlias
    AUnset Netgrplist    
  
    if [ -a $LDAPPASSWD ]; then
      `rm $LDAPPASSWD`
    fi

    if [ -a $LDAPGROUP ]; then
      `rm $LDAPGROUP`
    fi

    if [ -a $ldap_tmp ]; then 
      rm $ldap_tmp
    fi

    if [ -a $ldap_tmp1 ]; then 
      rm $ldap_tmp1
    fi
  fi      
fi  

PROCESSLDAP=0
Parse_User
Parse_Grp
Parse_Sudo
logInfo "Writing report"
report

case $SIG in            #4.3 Custom Signature
TSCM )
  NOTAREALID="NOTaRealID-TSCM"
  ;;
SCR )
  NOTAREALID="NOTaRealID-SCR"
  ;;
TCM ) 
  NOTAREALID="NOTaRealID-TCM"
  ;;
FUS )
  NOTAREALID="NOTaRealID-FUS"
  ;;
*)
  NOTAREALID="NOTaRealID"
  ;;
esac

typeset HOSTNAME=$HOST
if [[ $ENABLEFQDN -eq 1 && $FQDN -eq 1 ]]; then
  HOSTNAME=$LONG_HOST_NAME
fi

# adding dummy record
 if [[ $SCMFORMAT -eq 1 ]]; then 
    print -r "$HOSTNAME\t$OS\t$myAUDITDATE\t$NOTAREALID\t000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER\t1\t\t\t" >> $OUTPUTFILE
  elif [[ $MEF2FORMAT -eq 1 ]]; then
#MEF2 customer|system|account|userID convention data|group|state|l_logon|privilege
    print -r "$CUSTOMER|$HOSTNAME|$NOTAREALID|000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER||||" >> $OUTPUTFILE
  else
#MEF3 “customer|identifier type|server identifier/application identifier|OS name/Application name|account|UICMode|userID convention data|state|l_logon |group|privilege”
    print -r "$CUSTOMER|S|$HOSTNAME|$OS|$NOTAREALID||000/V///$myAUDITDATE:FN=$0:VER=$VERSION:CKSUM=$CKSUM:SUDO=$SUDOVER||||" >> $OUTPUTFILE
 fi

DATA=`APrintAll sudoUsers " "> $TMPFILE`

#APrintAll sudoUsers " "| while read nextline; do
while read nextline; do
  #echo  "SUDOERS: $nextline "
  set -A tokens `echo $nextline`
  userid=${tokens[0]}
  logMsg "WARNING" "invalid user in $SUDOERFILE: $userid"
  EXIT_CODE=1
  #let errorCount=errorCount+1
done < $TMPFILE

if [ -a $TMPFILE ]; then
rm $TMPFILE
fi

if [ errorCount -gt 0 ]; then
  logInfo "$errorCount errors encountered"
fi

Filter_mef3

if [[ $OWNER != "" ]]; then
    `chown $OWNER $OUTPUTFILE`
fi

logFooter

exit $EXIT_CODE
