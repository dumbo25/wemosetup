#! /usr/bin/env python3
"""
MyLog's goal is to add functionality to the logging module making it as easy
for me to use as print. Logging should be automatically used on every scrpt.

The logging module is very easy to use. So, a wrapper isn't necessary. However,
I don't want to relearn logging on the rare occasions when I am writing python
code. I'd prefer if everyone of my logfiles looked and behaved the same and I
never have to spend any time on logging.

I had a way to handle logging but it wasn't pythonic and it didn't use the
logging module. So, I am using logging and trying to make the module more
pythonic.

Turn Debug on by setting level to DEBUG

Modules or Tools that must be installed for script to work:
    None

References:
    Logging Cookbook:  https://doc.bccnsoft.com/docs/python-3.6.8-docs-html/howto/logging-cookbook.html#logging-cookbook
    Logging Cookbook:  https://docs.python.org/3/howto/logging-cookbook.html
    How To Logging:    https://doc.bccnsoft.com/docs/python-3.6.8-docs-html/howto/logging.html#logging-advanced-tutorial
    Python Logging:    https://realpython.com/python-logging-source-code/
    Loggly:            https://www.loggly.com/use-cases/python-syslog-how-to-set-up-and-troubleshoot/
    Loguru:            https://pythonrepo.com/repo/Delgan-loguru-python-generating-and-working-with-logs
                       I found Loguru when I was almost done with my version,
                       both have similar goals

My Guidelines for pythonic code:
    https://sites.google.com/site/cartwrightraspberrypiprojects/home/footer/pythonic
"""

############################# <- 80 Characters -> ##############################
#
# This style of commenting is called a garden bed and it is frowned upon by
# those who know python. But, I like it. I use a garden bed at the top to track
# my to do list as I work on the code, and then mark the completed To Dos. 
#
# Within the code, To Dos include a comment with ???, which makes it easy for 
# me to find
#
# Once the To Do list is more-or-less complete, I move the completed items into
# comments, docstrings or help within the code. Next, I remove the completed
# items.
#
# To Do List:
#
# Do later or not at all (I am tired of working on this):
#   g) add arguments from multiple scripts
#      use: https://www.doc.ic.ac.uk/~nuric/coding/argparse-with-multiple-files-to-handle-config$
#
# Won't Do:
#   k) are there any standard security features that can be added to logging
#      (e.g., don't print passwords, usernames) - It can be done, but it
#      requires a regexp to exclude each type of personal informaton to exclude
#   l) identify commands to use with arguments - this isn't really required
#
# Completed:
#
# To use logrotate, with install instructions and config rather than using
# python:
#   https://serverfault.com/questions/352942/equivalent-of-logrotate-on-osx
#
############################# <- 80 Characters -> ##############################

# Built-in Python3 Modules
import sys
import logging
import logging.handlers
import argparse
import os

# Modules that must be installed (pip3)

# My Modules (from github)

# Global Veriables (FirstUpper or CapWord)

# Global Constants (ALL CAPS)

# Classes
class MyLog:
    """ I want logging to be stupidly simple to use. So, I have no excuse to 
        use print instead of logging.
    """

    # LevelDict['INFO'] returns logging.INFO
    LevelDict = {"INFO":     logging.INFO,
                 "WARNING":  logging.WARNING,
                 "ERROR":    logging.ERROR,
                 "DEBUG":    logging.DEBUG,
                 "CRITICAL": logging.CRITICAL,
                 "NOTSET":   logging.NOTSET,
                }

    def __init__(self):
        """ MyLog() creates an object for the class, but may or may not do
            anything
        """

        # instance variables
        self.Logger = logging.getLogger("MyLog")

        # pylint complains if these aren't defined in __init__
        # I was using self.setProperties()
        # I could disable W0201, but I think this is a valuable check
        # insstance variables
        self.setLevel("INFO")

        # It might be reasonable to change size, filename and count to protected 
        # variables, and only change with a setter. I left these as accessible 
        # outside the the class to ease changing on reading in command line 
        # arguments.
        #
        # Changes only take effect after a call to openOutput.
        self.Size = 500000
        self.Count = 7
        # change filename
        self.Filename = "default.log"

        self.consoleHandler = ""

        # private instance variables
        # these should be access using logger.varName because things need to be 
        # set up or torn down when they change. I could have done these as 
        # protected variables.
        self.__Output = "BOTHUSR"

        # the next two lines are the main reason for the MyLog modulet, use it 
        # on everything! I always want log messages date and tiem stamped, which 
        # is accomplished using asctime
        self.fileFormatter = logging.Formatter('%(asctime)s: [%(levelname)s] %(filename)s:%(funcName)s:%(lineno)d \"%(message)s\"')
        self.consoleFormatter = logging.Formatter('%(message)s')

        # get only the script name - actually gets the name of ths file and not the script
        # self.Script = __file__.rsplit("/", 1)[1].split('.')[0]
        f = sys.argv[0]
        if f.find("/") != -1:
            self.Script = f.rsplit("/", 1)[1].split('.')[0]
        else:
            self.Script = f.split('.')[0]

        # if imported as a module, then open the output using defaults
        if self.Script != "mylog":
            self.openOutput()

    def setProperties(self, count=7, filename="default.log", level="INFO", 
                      output="BOTHUSR", size=500000):
        """ Set one or all properties for MyLog:
                count    = number of backups to keep (default = 7)
                filename = log file and path (depends on output setting)
                level    = types of messages to output to log file,such as,
                           INFO or DEBUG (default = INFO)
                output   = send to CONSOLE, SYS file, USR file, or both BOTHUSR,
                           BOTHSYS
                size     = size of backup file before log rotate 
                           (default = 500000)

           Use openOutput if satisfied with defaults
        """

        self.Count = count
        self.Filename = filename
        self.setLevel(level)
        self.Size = size
        self.__Output = output

        self.openOutput()

    def setOutput(self, output):
        """ change where logging is sent """

        self.__Output = output
        self.openOutput()

    def getOutput(self):
        """ returns Output, mosytly for testing """

        return self.__Output

    def openOutput(self):
        """ Opens the output (may be overridden by other settngs):
                SYS = /var/log/<script>/<script>.log
                USR = ~/<script>/<script>.log
                CONSOLE = output to stdout
                BOTHSYS = CONSOLE & SYS
                BOTHUSR = CONSOLE + USR

            Use log rotate to auto close and remove files based on count and size

            By default the RotatingFileHandler appends to a log file
        """

        self.Logger.setLevel(self.Logger.level)

        if self.__Output in ["SYS", "BOTHSYS"]:
            # check if running as sudo/root, if not exit
            if os.geteuid() != 0:
                print("Must run as sudo if output is SYS or BOTHSYS")
                sys.exit()

        # opens filename and creates a handler
        if self.__Output in ["SYS", "BOTHSYS", "USR", "BOTHUSR"]:
            self.createDirectory(self.Filename)
            self.fileHandler = logging.handlers.RotatingFileHandler(self.Filename,
                               maxBytes=self.Size, backupCount=self.Count)
            self.fileHandler.setFormatter(self.fileFormatter)
            self.Logger.addHandler(self.fileHandler)

        self.addConsole()

    def addConsole(self):
        """ Add console when required by output """
        # if old consoleHandler exists then remove it
        # also handles USR and SYS
        try:
            self.Logger.removeHandler(self.consoleHandler)
        except:
            pass

        # Console needs to be handled separately from file
        if self.__Output in ["CONSOLE", "BOTHSYS", "BOTHUSR"]:
            # CONSOLE outputs to stdout
            self.consoleHandler = logging.StreamHandler(sys.stdout)
            self.consoleHandler.setFormatter(self.consoleFormatter)
            self.Logger.addHandler(self.consoleHandler)

    def __enter__(self):
        return self.Logger

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.logPrint("INFO", "... Exiting " + self.Script)
        self.Logger.shutdown()

    def addPath(self, filename):
        """ Add a path to a filename if one doesn't exist """

        # if default filename, then replace with script name and extension
        f = filename
        if f == "default.log":
            f = self.Script + ".log"

        # if no path then add path
        if f.find("/"):
            if self.__Output in ["SYS", "BOTHSYS"]:
                f = "/var/log/" + self.Script + "/" + f
            elif self.__Output in ["USR", "BOTHUSR"]:
                cwd = os.getcwd()
                f = cwd + "/" + self.Script + "/" + f

        return f

    def createDirectory(self, filename):
        """ Create the needed directories for a filename's path """

        self.Filename = self.addPath(filename)

        directory = os.path.dirname(self.Filename)
        if not os.path.exists(directory):
            if directory != "":
                os.makedirs(directory)

    @staticmethod
    def closeMyLog(logger):
        """ if log file is opened, need to flush and close """

        logger.logPrint("INFO", "... shutting down logging")
        logging.shutdown()
        # exit doesn't go here, might need to exit with other messages

    def setFilename(self, filename):
        """ Sets filename instance variable for MyLog. The path, if any, is 
            contained within the filename. 

            This only sets the filename. Use openOutput or setProperties
            to write to the file.
        """
        name = __file__

        if filename in ["default.log", ""]:
            # Don't use default.log. Instead use the name of the script.log
            name = name[name.rfind("/")+1:name.find(".py")]
            filename = name + ".log"
            self.Filename = filename
        else:
            self.Filename = filename

    def setLevel(self, level):
        """ Sets level instance variable for log rotate handler in MyLog """
        self.Logger.setLevel(self.LevelDict[level])

    def getLevel(self):
        """ Returns log message level """

        # get the string associated with the numeric level
        #     Author: Stenio Elson
        #     Source: https://stackoverflow.com/questions/8023306/get-key-by-value-in-dictionary
        return list(self.LevelDict.keys())[list(self.LevelDict.values()).index(self.Logger.level)]

    def logPrint(self, level, message):
        """ Writes messages using the proper format and level to the log file """

        l = self.LevelDict[level]
        if l >= self.Logger.level:
            self.Logger.log(l, message)


class MyLogArguments:
    """ In order to run MyLog as a stand-alone script, then command line
        arguments are required to exercise and test its features
    """

    def __init__(self):
        self.parser = argparse.ArgumentParser(description='script 1.0')

        # for each argument add
        self.parser.add_argument('-c', '--count', help='log rotate count')
        self.parser.add_argument('-f', '--filename', help='log filename')
        self.parser.add_argument('-l', '--level', help='logging level = NOTSET, INFO, DEBUG, WARNING, ERROR, CRITICAL')
        self.parser.add_argument('-o', '--output', help='output = SYS, USR, CONSOLE, BOTHUSR, BOTHSYS')
        self.parser.add_argument('-s', '--size', help='log file size for rotate')

    def get(self):
        """ get the parser object """

        return self.parser.parse_args()

    def process(self, logger):
        """ process the command-line arguments """

        args = self.parser.parse_args()
        for arg in vars(args):
            v = str(getattr(args, arg))
            if str(v) != "None":
                if arg == "count":
                    logger.Count = int(v)
                elif arg == "filename":
                    logger.setFilename(v)
                elif arg == "level":
                    logger.setLevel(str(v))
                elif arg == "output":
                    logger.setOutput(str(v))
                elif arg == "size":
                    logger.Size = int(v)

    def help(self):
        """ -h, -help or no arguments """

        noArgs = True
        for k in self.parser.parse_args().__dict__:
            if self.parser.parse_args().__dict__[k] is not None:
                noArgs = False

        if noArgs:

            print('''
\033[1mNAME\033[0m
    MyLog -- MyLog adds functionality to the standard python module logging 
        making it stupidly easy for me to to use. Logging is easy to use, so a 
        wrapper isn't necessary. I just don't want to relearn logging on the 
        rare occasions when I am writing python code. I'd prefer if everyone of 
        my logfiles looked and behaved the same and I spend the minimum time on 
        logging.

        Logging is thread safe but not process safe.

\033[1mSYNOPSIS\033[0m
    Run as a script:
        python3 mylog.py [-options]

    Use as a module:
        On a MacBook:
            import sys
            sys.path.append("..")
            from mylog import MyLog

            logger = MyLog() 
            # Open filename for output or use logger.setProperties()
            logger.openOutput()
            logger.logPrint("logging message")

\033[1mDESCRIPTION\033[0m
    MyLog is used as a module to provide standard logging features with minimal
    relearning.

    The following commands are available. Each command has a corresponding
    method in the class. Commands may require an option.

        instance creation of logging object
            Every call requires a logging object, which is created using:

                import sys
                sys.path.append("..")
                from mylog import MyLog

                logger = MyLog(output="CONSOLE", filename="<__file__>.log", level=logging.INFO)
                # Open filename for output or use logger.setProperties()
                logger.openOutput()

                logger.logPrint("logging message")

            Only one logging instance should be created: logger = MyLog()

        logger.logPrint
            logger.logPrint(message, [level])
                Uses standard, controllable logging levels: CRITICAL, ERROR,
                WARNING, default=INFO, DEBUG, NOTSET

            Examples:
                logger.logPrint("message to print")
                logger.logPrint("error message", logging.ERROR)
                logger.logPrint("debugging info", logging.DEBUG)

            Log messages are printed in a standard format

        logger.setLogLevel(self, level):
            Examples:
                logger.setLevel("DEBUG")
                logger.setLevel("INFO")

     Options:
        -c --count <number>
           number of log rotate files

        -f -filename <name>
           log filename

        -l --level <level>
           logging level = CRITICAL, ERROR, WARNING, default=INFO, DEBUG, 
           NOTSET

        -o --output <output>
           Log messages can go to console, logfile or both using log to command
               output = SYS, USR, CONSOLE, BOTHSYS, BOTHUSR
               SYS means use /var/log/<name>/<name>.log and not /var/log/syslog
               BOTHSYS and BOTHUSR sends messages to both the console and a file

        -s --size <number>
           size of log file before it rotates


     Print above with docstrings uing the command (must include ./):
        $ pydoc ./mylog.py

''')
        # exit doesn't go here


class MyLogTest:
    """ Test cases for MyLog class """

    def __init__(self, logger):
        self.tests = True
        self.defaultCount = logger.Count
        self.defaultFilename = logger.Filename
        self.defaultLevel = logger.getLevel()
        self.defaultOutput = logger.getOutput()
        self.defaultSize = logger.Size

    def testPrintDefaults(self):
        """ print default values for comparison in test cases """

        print("    Defaults:")
        print("      count    = " + str(self.defaultCount))
        print("      filename = " + self.defaultFilename)
        print("      level    = " + self.defaultLevel)
        print("      output   = " + self.defaultOutput)
        print("      size     = " + str(self.defaultSize))

    @staticmethod
    def testPrintValues(logger):
        """ Print test case result """

        print("    Values:")
        print("      count    = " + str(logger.Count))
        print("      filename = " + logger.Filename)
        print("      level    = " + logger.getLevel())
        print("      output   = " + logger.getOutput())
        print("      size     = " + str(logger.Size))

    def testA1(self, logger):
        """ Test Case A.1: test default values """

        print("Test Case A.1 run with: python3 mylog.py -c 19")
        print("    check default values; count is set; need to run A.2 to check default of count")
        self.testPrintDefaults()
        self.testPrintValues(logger)

    @staticmethod
    def testA2():
        """ Test Case A.2: test default value of count """

        print("\nTest Case A.2 run with: python3 mylog.py -s 19")
        print("    check default value of count is set; need to run A.1 to check other defaults")

    def testB1(self, logger):
        """ Test Case B.1: test command line values """

        print("\nTest Case B.1 run with python3 mylog.py -c 3 -f testb1.log -l INFO -o BOTHUSR -s 325")
        self.testPrintDefaults()
        self.testPrintValues(logger)

    def testC1(self, logger):
        """ Test Case C.1: test values through method calls """

        print("\nTest Case C.1")
        self.testPrintDefaults()

        logger.Count = 72
        logger.setFilename("rosie.log")
        logger.setLevel("CRITICAL")
        logger.setOutput("USR")
        logger.Size = 67

        self.testPrintValues(logger)

    @staticmethod
    def testD1(logger):
        """ Test Case D.1: test if level works """

        logger.setLevel("INFO")
        print("\nTest Case D.1")
        print("    INFO", """level tests:
    D.1.a. Set Level <level>
    D.1.a. INFO message
    D.1.b. Set level INFO
    D.1.b. INFO message
    D.1.c. Set level DEBUG
    D.1.c. DEBUG message
    D.1.c. INFO message""")

        logger.logPrint("INFO", "D.1.a. Set level " + logger.getLevel())
        logger.setLevel("INFO")
        logger.logPrint("DEBUG", "D.1.a. DEBUG message - should not see this")
        logger.logPrint("INFO", "D.1.a. INFO message - should see this")

        logger.logPrint("INFO", "D.1.b. Set level INFO")
        logger.setLevel("INFO")
        logger.logPrint("DEBUG", "D.1.b. DEBUG message - should not see this")
        logger.logPrint("INFO", "D.1.b. INFO message - should see this")

        logger.logPrint("INFO", "D.1.c. Set level DEBUG")
        logger.setLevel("DEBUG")
        logger.logPrint("DEBUG", "DEBUG message - should see this")
        logger.logPrint("INFO", "INFO messag - should see thise")

    @staticmethod
    def testE1(logger):
        """ Test Case E.1: test if level works """

        print("\nTest Case E.1: check if Output works as expected")
        logger.setLevel("INFO")
        logger.setOutput("BOTHUSR")
        logger.logPrint("INFO", "E.1.a. Output = " + logger.getOutput())
        logger.logPrint("INFO", "E.1.b. This goes to both the console and file")
        logger.setOutput("USR")
        logger.logPrint("INFO", "E.1.c. This only goes to the file, and not the console")


# function definitions
def main():
    """ Example script on how to use MyLog stand alone or to test """

    # get the logger object
    logger = MyLog()
    t = MyLogTest(logger)

    # set the values for MyLog from the command-line arguments
    a = MyLogArguments()
    args = a.get()
    a.process(logger)

    # open the file and/or console for MyLog
    # as a script, the arguments must be processed before the output is opened
    logger.openOutput()

    logger.logPrint("INFO", "Starting MyLog ...")

    logger.logPrint("INFO", "args = " + str(args))

    # include test cases for future changes
    t.testA1(logger)
    t.testA2()
    t.testB1(logger)
    t.testC1(logger)
    t.testD1(logger)
    t.testE1(logger)

    a.help()

    logger.logPrint("INFO", "message to user file")

    logger.closeMyLog(logger)

# In every script, ALWAYS use an if main
if __name__ == "__main__":
    main()
