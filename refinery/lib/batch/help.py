from __future__ import annotations

from inspect import getdoc


def _help(cls: type):
    name = cls.__name__
    help = getdoc(cls) or ''
    HelpOutput[name] = help
    return help


HelpOutput: dict[str, str] = {}


@_help
class CALL:
    """
    Calls one batch program from another.

    CALL [drive:][path]filename [batch-parameters]

      batch-parameters   Specifies any command-line information required by the
                         batch program.

    If Command Extensions are enabled CALL changes as follows:

    CALL command now accepts labels as the target of the CALL.  The syntax
    is:

        CALL :label arguments

    A new batch file context is created with the specified arguments and
    control is passed to the statement after the label specified.  You must
    "exit" twice by reaching the end of the batch script file twice.  The
    first time you read the end, control will return to just after the CALL
    statement.  The second time will exit the batch script.  Type GOTO /?
    for a description of the GOTO :EOF extension that will allow you to
    "return" from a batch script.

    In addition, expansion of batch script argument references (%0, %1,
    etc.) have been changed as follows:


        %* in a batch script refers to all the arguments (e.g. %1 %2 %3
            %4 %5 ...)

        Substitution of batch parameters (%n) has been enhanced.  You can
        now use the following optional syntax:

            %~1         - expands %1 removing any surrounding quotes (")
            %~f1        - expands %1 to a fully qualified path name
            %~d1        - expands %1 to a drive letter only
            %~p1        - expands %1 to a path only
            %~n1        - expands %1 to a file name only
            %~x1        - expands %1 to a file extension only
            %~s1        - expanded path contains short names only
            %~a1        - expands %1 to file attributes
            %~t1        - expands %1 to date/time of file
            %~z1        - expands %1 to size of file
            %~$PATH:1   - searches the directories listed in the PATH
                           environment variable and expands %1 to the fully
                           qualified name of the first one found.  If the
                           environment variable name is not defined or the
                           file is not found by the search, then this
                           modifier expands to the empty string

        The modifiers can be combined to get compound results:

            %~dp1       - expands %1 to a drive letter and path only
            %~nx1       - expands %1 to a file name and extension only
            %~dp$PATH:1 - searches the directories listed in the PATH
                           environment variable for %1 and expands to the
                           drive letter and path of the first one found.
            %~ftza1     - expands %1 to a DIR like output line

        In the above examples %1 and PATH can be replaced by other
        valid values.  The %~ syntax is terminated by a valid argument
        number.  The %~ modifiers may not be used with %*
    """


@_help
class SET:
    """
    Displays, sets, or removes cmd.exe environment variables.

    SET [variable=[string]]

      variable  Specifies the environment-variable name.
      string    Specifies a series of characters to assign to the variable.

    Type SET without parameters to display the current environment variables.

    If Command Extensions are enabled SET changes as follows:

    SET command invoked with just a variable name, no equal sign or value
    will display the value of all variables whose prefix matches the name
    given to the SET command.  For example:

        SET P

    would display all variables that begin with the letter 'P'

    SET command will set the ERRORLEVEL to 1 if the variable name is not
    found in the current environment.

    SET command will not allow an equal sign to be part of the name of
    a variable.

    Two new switches have been added to the SET command:

        SET /A expression
        SET /P variable=[promptString]

    The /A switch specifies that the string to the right of the equal sign
    is a numerical expression that is evaluated.  The expression evaluator
    is pretty simple and supports the following operations, in decreasing
    order of precedence:

        ()                  - grouping
        ! ~ -               - unary operators
        * / %               - arithmetic operators
        + -                 - arithmetic operators
        << >>               - logical shift
        &                   - bitwise and
        ^                   - bitwise exclusive or
        |                   - bitwise or
        = *= /= %= += -=    - assignment
          &= ^= |= <<= >>=
        ,                   - expression separator

    If you use any of the logical or modulus operators, you will need to
    enclose the expression string in quotes.  Any non-numeric strings in the
    expression are treated as environment variable names whose values are
    converted to numbers before using them.  If an environment variable name
    is specified but is not defined in the current environment, then a value
    of zero is used.  This allows you to do arithmetic with environment
    variable values without having to type all those % signs to get their
    values.  If SET /A is executed from the command line outside of a
    command script, then it displays the final value of the expression.  The
    assignment operator requires an environment variable name to the left of
    the assignment operator.  Numeric values are decimal numbers, unless
    prefixed by 0x for hexadecimal numbers, and 0 for octal numbers.
    So 0x12 is the same as 18 is the same as 022. Please note that the octal
    notation can be confusing: 08 and 09 are not valid numbers because 8 and
    9 are not valid octal digits.

    The /P switch allows you to set the value of a variable to a line of input
    entered by the user.  Displays the specified promptString before reading
    the line of input.  The promptString can be empty.

    Environment variable substitution has been enhanced as follows:

        %PATH:str1=str2%

    would expand the PATH environment variable, substituting each occurrence
    of "str1" in the expanded result with "str2".  "str2" can be the empty
    string to effectively delete all occurrences of "str1" from the expanded
    output.  "str1" can begin with an asterisk, in which case it will match
    everything from the beginning of the expanded output to the first
    occurrence of the remaining portion of str1.

    May also specify substrings for an expansion.

        %PATH:~10,5%

    would expand the PATH environment variable, and then use only the 5
    characters that begin at the 11th (offset 10) character of the expanded
    result.  If the length is not specified, then it defaults to the
    remainder of the variable value.  If either number (offset or length) is
    negative, then the number used is the length of the environment variable
    value added to the offset or length specified.

        %PATH:~-10%

    would extract the last 10 characters of the PATH variable.

        %PATH:~0,-2%

    would extract all but the last 2 characters of the PATH variable.

    Finally, support for delayed environment variable expansion has been
    added.  This support is always disabled by default, but may be
    enabled/disabled via the /V command line switch to CMD.EXE.  See CMD /?

    Delayed environment variable expansion is useful for getting around
    the limitations of the current expansion which happens when a line
    of text is read, not when it is executed.  The following example
    demonstrates the problem with immediate variable expansion:

        set VAR=before
        if "%VAR%" == "before" (
            set VAR=after
            if "%VAR%" == "after" @echo If you see this, it worked
        )

    would never display the message, since the %VAR% in BOTH IF statements
    is substituted when the first IF statement is read, since it logically
    includes the body of the IF, which is a compound statement.  So the
    IF inside the compound statement is really comparing "before" with
    "after" which will never be equal.  Similarly, the following example
    will not work as expected:

        set LIST=
        for %i in (*) do set LIST=%LIST% %i
        echo %LIST%

    in that it will NOT build up a list of files in the current directory,
    but instead will just set the LIST variable to the last file found.
    Again, this is because the %LIST% is expanded just once when the
    FOR statement is read, and at that time the LIST variable is empty.
    So the actual FOR loop we are executing is:

        for %i in (*) do set LIST= %i

    which just keeps setting LIST to the last file found.

    Delayed environment variable expansion allows you to use a different
    character (the exclamation mark) to expand environment variables at
    execution time.  If delayed variable expansion is enabled, the above
    examples could be written as follows to work as intended:

        set VAR=before
        if "%VAR%" == "before" (
            set VAR=after
            if "!VAR!" == "after" @echo If you see this, it worked
        )

        set LIST=
        for %i in (*) do set LIST=!LIST! %i
        echo %LIST%

    If Command Extensions are enabled, then there are several dynamic
    environment variables that can be expanded but which don't show up in
    the list of variables displayed by SET.  These variable values are
    computed dynamically each time the value of the variable is expanded.
    If the user explicitly defines a variable with one of these names, then
    that definition will override the dynamic one described below:

    %CD% - expands to the current directory string.

    %DATE% - expands to current date using same format as DATE command.

    %TIME% - expands to current time using same format as TIME command.

    %RANDOM% - expands to a random decimal number between 0 and 32767.

    %ERRORLEVEL% - expands to the current ERRORLEVEL value

    %CMDEXTVERSION% - expands to the current Command Processor Extensions
        version number.

    %CMDCMDLINE% - expands to the original command line that invoked the
        Command Processor.

    %HIGHESTNUMANODENUMBER% - expands to the highest NUMA node number
        on this machine.
    """


@_help
class SETLOCAL:
    """
    Begins localization of environment changes in a batch file.  Environment
    changes made after SETLOCAL has been issued are local to the batch file.
    ENDLOCAL must be issued to restore the previous settings.  When the end
    of a batch script is reached, an implied ENDLOCAL is executed for any
    outstanding SETLOCAL commands issued by that batch script.

    SETLOCAL

    If Command Extensions are enabled SETLOCAL changes as follows:

    SETLOCAL batch command now accepts optional arguments:
            ENABLEEXTENSIONS / DISABLEEXTENSIONS
                enable or disable command processor extensions. These
                arguments takes precedence over the CMD /E:ON or /E:OFF
                switches. See CMD /? for details.
            ENABLEDELAYEDEXPANSION / DISABLEDELAYEDEXPANSION
                enable or disable delayed environment variable
                expansion. These arguments takes precedence over the CMD
                /V:ON or /V:OFF switches. See CMD /? for details.
    These modifications last until the matching ENDLOCAL command,
    regardless of their setting prior to the SETLOCAL command.

    The SETLOCAL command will set the ERRORLEVEL value if given
    an argument.  It will be zero if one of the two valid arguments
    is given and one otherwise.  You can use this in batch scripts
    to determine if the extensions are available, using the following
    technique:

        VERIFY OTHER 2>nul
        SETLOCAL ENABLEEXTENSIONS
        IF ERRORLEVEL 1 echo Unable to enable extensions

    This works because on old versions of CMD.EXE, SETLOCAL does NOT
    set the ERRORLEVEL value. The VERIFY command with a bad argument
    initializes the ERRORLEVEL value to a non-zero value.
    """


@_help
class ENDLOCAL:
    """
    Ends localization of environment changes in a batch file.
    Environment changes made after ENDLOCAL has been issued are
    not local to the batch file; the previous settings are not
    restored on termination of the batch file.

    ENDLOCAL

    If Command Extensions are enabled ENDLOCAL changes as follows:

    If the corresponding SETLOCAL enable or disabled command extensions
    using the new ENABLEEXTENSIONS or DISABLEEXTENSIONS options, then
    after the ENDLOCAL, the enabled/disabled state of command extensions
    will be restored to what it was prior to the matching SETLOCAL
    command execution.
    """


@_help
class GOTO:
    """
    Directs cmd.exe to a labeled line in a batch program.

    GOTO label

      label   Specifies a text string used in the batch program as a label.

    You type a label on a line by itself, beginning with a colon.

    If Command Extensions are enabled GOTO changes as follows:

    GOTO command now accepts a target label of :EOF which transfers control
    to the end of the current batch script file.  This is an easy way to
    exit a batch script file without defining a label.  Type CALL /?  for a
    description of extensions to the CALL command that make this feature
    useful.

    Executing GOTO :EOF after a CALL with a target label will return control
    to the statement immediately following the CALL.
    """


@_help
class EXIT:
    """
    Quits the CMD.EXE program (command interpreter) or the current batch
    script.

    EXIT [/B] [exitCode]

      /B          specifies to exit the current batch script instead of
                  CMD.EXE.  If executed from outside a batch script, it
                  will quit CMD.EXE

      exitCode    specifies a numeric number.  if /B is specified, sets
                  ERRORLEVEL that number.  If quitting CMD.EXE, sets the process
                  exit code with that number.

    If Command Extensions are enabled EXIT changes as follows:

    Executing EXIT /B after a CALL with a target label will return control
    to the statement immediately following the CALL.
    """


@_help
class CHDIR:
    r"""
    Displays the name of or changes the current directory.

    CHDIR [/D] [drive:][path]
    CHDIR [..]
    CD [/D] [drive:][path]
    CD [..]

      ..   Specifies that you want to change to the parent directory.

    Type CD drive: to display the current directory in the specified drive.
    Type CD without parameters to display the current drive and directory.

    Use the /D switch to change current drive in addition to changing current
    directory for a drive.

    If Command Extensions are enabled CHDIR changes as follows:

    The current directory string is converted to use the same case as
    the on disk names.  So CD C:\TEMP would actually set the current
    directory to C:\Temp if that is the case on disk.

    CHDIR command does not treat spaces as delimiters, so it is possible to
    CD into a subdirectory name that contains a space without surrounding
    the name with quotes.  For example:

        cd \winnt\profiles\username\programs\start menu

    is the same as:

        cd "\winnt\profiles\username\programs\start menu"

    which is what you would have to type if extensions were disabled.
    """


@_help
class PUSHD:
    """
    Stores the current directory for use by the POPD command, then
    changes to the specified directory.

    PUSHD [path | ..]

    path        Specifies the directory to make the current directory.

    If Command Extensions are enabled the PUSHD command accepts
    network paths in addition to the normal drive letter and path.
    If a network path is specified, PUSHD will create a temporary
    drive letter that points to that specified network resource and
    then change the current drive and directory, using the newly
    defined drive letter.  Temporary drive letters are allocated from
    Z: on down, using the first unused drive letter found.
    """


@_help
class POPD:
    """
    Changes to the directory stored by the PUSHD command.

    POPD


    If Command Extensions are enabled the POPD command will delete
    any temporary drive letter created by PUSHD when you POPD that
    drive off the pushed directory stack.
    """


@_help
class ECHO:
    """
    Displays messages, or turns command-echoing on or off.

    ECHO [ON | OFF]
    ECHO [message]

    Type ECHO without parameters to display the current echo setting.
    """


@_help
class DEL:
    """
    Deletes one or more files.

    DEL [/P] [/F] [/S] [/Q] [/A[[:]attributes]] names
    ERASE [/P] [/F] [/S] [/Q] [/A[[:]attributes]] names

      names         Specifies a list of one or more files or directories.
                    Wildcards may be used to delete multiple files. If a
                    directory is specified, all files within the directory
                    will be deleted.

      /P            Prompts for confirmation before deleting each file.
      /F            Force deleting of read-only files.
      /S            Delete specified files from all subdirectories.
      /Q            Quiet mode, do not ask if ok to delete on global wildcard
      /A            Selects files to delete based on attributes
      attributes    R  Read-only files            S  System files
                    H  Hidden files               A  Files ready for archiving
                    I  Not content indexed Files  L  Reparse Points
                    O  Offline files              -  Prefix meaning not

    If Command Extensions are enabled DEL and ERASE change as follows:

    The display semantics of the /S switch are reversed in that it shows
    you only the files that are deleted, not the ones it could not find.
    """


@_help
class FOR:
    """
    Runs a specified command for each file in a set of files.

    FOR %variable IN (set) DO command [command-parameters]

      %variable  Specifies a single letter replaceable parameter.
      (set)      Specifies a set of one or more files.  Wildcards may be used.
      command    Specifies the command to carry out for each file.
      command-parameters
                 Specifies parameters or switches for the specified command.

    To use the FOR command in a batch program, specify %%variable instead
    of %variable.  Variable names are case sensitive, so %i is different
    from %I.

    If Command Extensions are enabled, the following additional
    forms of the FOR command are supported:

    FOR /D %variable IN (set) DO command [command-parameters]

        If set contains wildcards, then specifies to match against directory
        names instead of file names.

    FOR /R [[drive:]path] %variable IN (set) DO command [command-parameters]

        Walks the directory tree rooted at [drive:]path, executing the FOR
        statement in each directory of the tree.  If no directory
        specification is specified after /R then the current directory is
        assumed.  If set is just a single period (.) character then it
        will just enumerate the directory tree.

    FOR /L %variable IN (start,step,end) DO command [command-parameters]

        The set is a sequence of numbers from start to end, by step amount.
        So (1,1,5) would generate the sequence 1 2 3 4 5 and (5,-1,1) would
        generate the sequence (5 4 3 2 1)

    FOR /F ["options"] %variable IN (file-set) DO command [command-parameters]
    FOR /F ["options"] %variable IN ("string") DO command [command-parameters]
    FOR /F ["options"] %variable IN ('command') DO command [command-parameters]

        or, if usebackq option present:

    FOR /F ["options"] %variable IN (file-set) DO command [command-parameters]
    FOR /F ["options"] %variable IN ('string') DO command [command-parameters]
    FOR /F ["options"] %variable IN (`command`) DO command [command-parameters]

        file-set is one or more file names.  Each file is opened, read
        and processed before going on to the next file in file-set.
        Processing consists of reading in the file, breaking it up into
        individual lines of text and then parsing each line into zero or
        more tokens.  The body of the for loop is then called with the
        variable value(s) set to the found token string(s).  By default, /F
        passes the first blank separated token from each line of each file.
        Blank lines are skipped.  You can override the default parsing
        behavior by specifying the optional "options" parameter.  This
        is a quoted string which contains one or more keywords to specify
        different parsing options.  The keywords are:

            eol=c           - specifies an end of line comment character
                              (just one)
            skip=n          - specifies the number of lines to skip at the
                              beginning of the file.
            delims=xxx      - specifies a delimiter set.  This replaces the
                              default delimiter set of space and tab.
            tokens=x,y,m-n  - specifies which tokens from each line are to
                              be passed to the for body for each iteration.
                              This will cause additional variable names to
                              be allocated.  The m-n form is a range,
                              specifying the mth through the nth tokens.  If
                              the last character in the tokens= string is an
                              asterisk, then an additional variable is
                              allocated and receives the remaining text on
                              the line after the last token parsed.
            usebackq        - specifies that the new semantics are in force,
                              where a back quoted string is executed as a
                              command and a single quoted string is a
                              literal string command and allows the use of
                              double quotes to quote file names in
                              file-set.

        Some examples might help:

    FOR /F "eol=; tokens=2,3* delims=, " %i in (myfile.txt) do @echo %i %j %k

        would parse each line in myfile.txt, ignoring lines that begin with
        a semicolon, passing the 2nd and 3rd token from each line to the for
        body, with tokens delimited by commas and/or spaces.  Notice the for
        body statements reference %i to get the 2nd token, %j to get the
        3rd token, and %k to get all remaining tokens after the 3rd.  For
        file names that contain spaces, you need to quote the filenames with
        double quotes.  In order to use double quotes in this manner, you also
        need to use the usebackq option, otherwise the double quotes will be
        interpreted as defining a literal string to parse.

        %i is explicitly declared in the for statement and the %j and %k
        are implicitly declared via the tokens= option.  You can specify up
        to 26 tokens via the tokens= line, provided it does not cause an
        attempt to declare a variable higher than the letter 'z' or 'Z'.
        Remember, FOR variables are single-letter, case sensitive, global,
        and you can't have more than 52 total active at any one time.

        You can also use the FOR /F parsing logic on an immediate string, by
        making the file-set between the parenthesis a quoted string,
        using single quote characters.  It will be treated as a single line
        of input from a file and parsed.

        Finally, you can use the FOR /F command to parse the output of a
        command.  You do this by making the file-set between the
        parenthesis a back quoted string.  It will be treated as a command
        line, which is passed to a child CMD.EXE and the output is captured
        into memory and parsed as if it was a file.  So the following
        example:

          FOR /F "usebackq delims==" %i IN (`set`) DO @echo %i

        would enumerate the environment variable names in the current
        environment.

    In addition, substitution of FOR variable references has been enhanced.
    You can now use the following optional syntax:

        %~I         - expands %I removing any surrounding quotes (")
        %~fI        - expands %I to a fully qualified path name
        %~dI        - expands %I to a drive letter only
        %~pI        - expands %I to a path only
        %~nI        - expands %I to a file name only
        %~xI        - expands %I to a file extension only
        %~sI        - expanded path contains short names only
        %~aI        - expands %I to file attributes of file
        %~tI        - expands %I to date/time of file
        %~zI        - expands %I to size of file
        %~$PATH:I   - searches the directories listed in the PATH
                       environment variable and expands %I to the
                       fully qualified name of the first one found.
                       If the environment variable name is not
                       defined or the file is not found by the
                       search, then this modifier expands to the
                       empty string

    The modifiers can be combined to get compound results:

        %~dpI       - expands %I to a drive letter and path only
        %~nxI       - expands %I to a file name and extension only
        %~fsI       - expands %I to a full path name with short names only
        %~dp$PATH:I - searches the directories listed in the PATH
                       environment variable for %I and expands to the
                       drive letter and path of the first one found.
        %~ftzaI     - expands %I to a DIR like output line

    In the above examples %I and PATH can be replaced by other valid
    values.  The %~ syntax is terminated by a valid FOR variable name.
    Picking upper case variable names like %I makes it more readable and
    avoids confusion with the modifiers, which are not case sensitive.
    """


@_help
class IF:
    """
    Performs conditional processing in batch programs.

    IF [NOT] ERRORLEVEL number command
    IF [NOT] string1==string2 command
    IF [NOT] EXIST filename command

      NOT               Specifies that Windows should carry out
                        the command only if the condition is false.

      ERRORLEVEL number Specifies a true condition if the last program run
                        returned an exit code equal to or greater than the number
                        specified.

      string1==string2  Specifies a true condition if the specified text strings
                        match.

      EXIST filename    Specifies a true condition if the specified filename
                        exists.

      command           Specifies the command to carry out if the condition is
                        met.  Command can be followed by ELSE command which
                        will execute the command after the ELSE keyword if the
                        specified condition is FALSE

    The ELSE clause must occur on the same line as the command after the IF.  For
    example:

        IF EXIST filename. (
            del filename.
        ) ELSE (
            echo filename. missing.
        )

    The following would NOT work because the del command needs to be terminated
    by a newline:

        IF EXIST filename. del filename. ELSE echo filename. missing

    Nor would the following work, since the ELSE command must be on the same line
    as the end of the IF command:

        IF EXIST filename. del filename.
        ELSE echo filename. missing

    The following would work if you want it all on one line:

        IF EXIST filename. (del filename.) ELSE echo filename. missing

    If Command Extensions are enabled IF changes as follows:

        IF [/I] string1 compare-op string2 command
        IF CMDEXTVERSION number command
        IF DEFINED variable command

    where compare-op may be one of:

        EQU - equal
        NEQ - not equal
        LSS - less than
        LEQ - less than or equal
        GTR - greater than
        GEQ - greater than or equal

    and the /I switch, if specified, says to do case insensitive string
    compares.  The /I switch can also be used on the string1==string2 form
    of IF.  These comparisons are generic, in that if both string1 and
    string2 are both comprised of all numeric digits, then the strings are
    converted to numbers and a numeric comparison is performed.

    The CMDEXTVERSION conditional works just like ERRORLEVEL, except it is
    comparing against an internal version number associated with the Command
    Extensions.  The first version is 1.  It will be incremented by one when
    significant enhancements are added to the Command Extensions.
    CMDEXTVERSION conditional is never true when Command Extensions are
    disabled.

    The DEFINED conditional works just like EXIST except it takes an
    environment variable name and returns true if the environment variable
    is defined.

    %ERRORLEVEL% will expand into a string representation of
    the current value of ERRORLEVEL, provided that there is not already
    an environment variable with the name ERRORLEVEL, in which case you
    will get its value instead.  After running a program, the following
    illustrates ERRORLEVEL use:

        goto answer%ERRORLEVEL%
        :answer0
        echo Program had return code 0
        :answer1
        echo Program had return code 1

    You can also use numerical comparisons above:

        IF %ERRORLEVEL% LEQ 1 goto okay

    %CMDCMDLINE% will expand into the original command line passed to
    CMD.EXE prior to any processing by CMD.EXE, provided that there is not
    already an environment variable with the name CMDCMDLINE, in which case
    you will get its value instead.

    %CMDEXTVERSION% will expand into a string representation of the
    current value of CMDEXTVERSION, provided that there is not already
    an environment variable with the name CMDEXTVERSION, in which case you
    will get its value instead.
    """


@_help
class FINDSTR:
    r"""
    Searches for strings in files.

    FINDSTR [/B] [/E] [/L] [/R] [/S] [/I] [/X] [/V] [/N] [/M] [/O] [/P] [/F:file]
            [/C:string] [/G:file] [/D:dir list] [/A:color attributes] [/OFF[LINE]]
            strings [[drive:][path]filename[ ...]]

    /B         Matches pattern if at the beginning of a line.
    /E         Matches pattern if at the end of a line.
    /L         Uses search strings literally.
    /R         Uses search strings as regular expressions.
    /S         Searches for matching files in the current directory and all
               subdirectories.
    /I         Specifies that the search is not to be case-sensitive.
    /X         Prints lines that match exactly.
    /V         Prints only lines that do not contain a match.
    /N         Prints the line number before each line that matches.
    /M         Prints only the filename if a file contains a match.
    /O         Prints character offset before each matching line.
    /P         Skip files with non-printable characters.
    /OFF[LINE] Do not skip files with offline attribute set.
    /A:attr    Specifies color attribute with two hex digits. See "color /?"
    /F:file    Reads file list from the specified file(/ stands for console).
    /C:string  Uses specified string as a literal search string.
    /G:file    Gets search strings from the specified file(/ stands for console).
    /D:dir     Search a semicolon delimited list of directories
    /Q:qflags  Quiet mode flags:
               u           Suppress warning about unsupported Unicode formats
    strings    Text to be searched for.
    [drive:][path]filename
               Specifies a file or files to search.

    Use spaces to separate multiple search strings unless the argument is prefixed
    with /C.  For example, 'FINDSTR "hello there" x.y' searches for "hello" or
    "there" in file x.y.  'FINDSTR /C:"hello there" x.y' searches for
    "hello there" in file x.y.

    Regular expression quick reference:
    .        Wildcard: any character
    *        Repeat: zero or more occurrences of previous character or class
    ^        Line position: beginning of line
    $        Line position: end of line
    [class]  Character class: any one character in set
    [^class] Inverse class: any one character not in set
    [x-y]    Range: any characters within the specified range
    \x       Escape: literal use of metacharacter x
    \<xyz    Word position: beginning of word
    xyz\>    Word position: end of word

    For full information on FINDSTR regular expressions refer to the online Command
    Reference.
    """


@_help
class FIND:
    """
    Searches for a text string in a file or files.

    FIND [/V] [/C] [/N] [/I] [/OFF[LINE]] "string" [[drive:][path]filename[ ...]]

    /V         Displays all lines NOT containing the specified string.
    /C         Displays only the count of lines containing the string.
    /N         Displays line numbers with the displayed lines.
    /I         Ignores the case of characters when searching for the string.
    /OFF[LINE] Do not skip files with offline attribute set.
    "string"   Specifies the text string to find.
    [drive:][path]filename
                Specifies a file or files to search.

    If a path is not specified, FIND searches the text typed at the prompt
    or piped from another command.
    """


@_help
class CLS:
    """
    Clears the screen.

    CLS
    """


@_help
class TYPE:
    """
    Displays the contents of a text file or files.

    TYPE [drive:][path]filename
    """


@_help
class HELP:
    """
    For more information on a specific command, type HELP command-name
    ASSOC          Displays or modifies file extension associations.
    ATTRIB         Displays or changes file attributes.
    BREAK          Sets or clears extended CTRL+C checking.
    BCDEDIT        Sets properties in boot database to control boot loading.
    CACLS          Displays or modifies access control lists (ACLs) of files.
    CALL           Calls one batch program from another.
    CD             Displays the name of or changes the current directory.
    CHCP           Displays or sets the active code page number.
    CHDIR          Displays the name of or changes the current directory.
    CHKDSK         Checks a disk and displays a status report.
    CHKNTFS        Displays or modifies the checking of disk at boot time.
    CLS            Clears the screen.
    CMD            Starts a new instance of the Windows command interpreter.
    COLOR          Sets the default console foreground and background colors.
    COMP           Compares the contents of two files or sets of files.
    COMPACT        Displays or alters the compression of files on NTFS partitions.
    CONVERT        Converts FAT volumes to NTFS.  You cannot convert the
                   current drive.
    COPY           Copies one or more files to another location.
    DATE           Displays or sets the date.
    DEL            Deletes one or more files.
    DIR            Displays a list of files and subdirectories in a directory.
    DISKPART       Displays or configures Disk Partition properties.
    DOSKEY         Edits command lines, recalls Windows commands, and\x20
                   creates macros.
    DRIVERQUERY    Displays current device driver status and properties.
    ECHO           Displays messages, or turns command echoing on or off.
    ENDLOCAL       Ends localization of environment changes in a batch file.
    ERASE          Deletes one or more files.
    EXIT           Quits the CMD.EXE program (command interpreter).
    FC             Compares two files or sets of files, and displays the\x20
                   differences between them.
    FIND           Searches for a text string in a file or files.
    FINDSTR        Searches for strings in files.
    FOR            Runs a specified command for each file in a set of files.
    FORMAT         Formats a disk for use with Windows.
    FSUTIL         Displays or configures the file system properties.
    FTYPE          Displays or modifies file types used in file extension\x20
                   associations.
    GOTO           Directs the Windows command interpreter to a labeled line in\x20
                   a batch program.
    GPRESULT       Displays Group Policy information for machine or user.
    HELP           Provides Help information for Windows commands.
    ICACLS         Display, modify, backup, or restore ACLs for files and\x20
                   directories.
    IF             Performs conditional processing in batch programs.
    LABEL          Creates, changes, or deletes the volume label of a disk.
    MD             Creates a directory.
    MKDIR          Creates a directory.
    MKLINK         Creates Symbolic Links and Hard Links
    MODE           Configures a system device.
    MORE           Displays output one screen at a time.
    MOVE           Moves one or more files from one directory to another\x20
                   directory.
    OPENFILES      Displays files opened by remote users for a file share.
    PATH           Displays or sets a search path for executable files.
    PAUSE          Suspends processing of a batch file and displays a message.
    POPD           Restores the previous value of the current directory saved by\x20
                   PUSHD.
    PRINT          Prints a text file.
    PROMPT         Changes the Windows command prompt.
    PUSHD          Saves the current directory then changes it.
    RD             Removes a directory.
    RECOVER        Recovers readable information from a bad or defective disk.
    REM            Records comments (remarks) in batch files or CONFIG.SYS.
    REN            Renames a file or files.
    RENAME         Renames a file or files.
    REPLACE        Replaces files.
    RMDIR          Removes a directory.
    ROBOCOPY       Advanced utility to copy files and directory trees
    SET            Displays, sets, or removes Windows environment variables.
    SETLOCAL       Begins localization of environment changes in a batch file.
    SC             Displays or configures services (background processes).
    SCHTASKS       Schedules commands and programs to run on a computer.
    SHIFT          Shifts the position of replaceable parameters in batch files.
    SHUTDOWN       Allows proper local or remote shutdown of machine.
    SORT           Sorts input.
    START          Starts a separate window to run a specified program or command.
    SUBST          Associates a path with a drive letter.
    SYSTEMINFO     Displays machine specific properties and configuration.
    TASKLIST       Displays all currently running tasks including services.
    TASKKILL       Kill or stop a running process or application.
    TIME           Displays or sets the system time.
    TITLE          Sets the window title for a CMD.EXE session.
    TREE           Graphically displays the directory structure of a drive or\x20
                   path.
    TYPE           Displays the contents of a text file.
    VER            Displays the Windows version.
    VERIFY         Tells Windows whether to verify that your files are written
                   correctly to a disk.
    VOL            Displays a disk volume label and serial number.
    XCOPY          Copies files and directory trees.
    WMIC           Displays WMI information inside interactive command shell.

    For more information on tools see the command-line reference in the online help.
    """
