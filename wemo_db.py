#! /usr/bin/env python3
"""
wemo_db.py records and tracks data about WeMo devices.

Modules or Tools that must be installed for script to work:
    None

References:
    Real Python: SQL Injection, https://realpython.com/prevent-python-sql-injection/
    Mitre: CVE SQL vulnerabilities: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=sql
    PYnative: prepared statements: https://pynative.com/python-mysql-execute-parameterized-query-using-prepared-statement/

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
# ******************** ????  STOPPED HERE ???? ********************
#                      WORKING ON ??? in code
#
#      ??? mac command needs to have some type of output
#   b) create table for failure
#          MAC-Address, failureType, Description, timeStamp
#          MAC-Address or IP-Address is in table, but on new run of discover command IP or MAC Address is not discovered
#   d) my ...
#      d.1) excel sheet: Room, Circuit, SSID, ID
#      d.2) raspberry pi projects: https://sites.google.com/site/cartwrightraspberrypiprojects/home/home-automation-categories/lighting/smart-wi-fi-switches-by-room?authuser=0
#   f) add command to clear database and start over (rerun initialize)
#   g) add something to record failures automatically
#   h) add command to add a manual failure
#   i) integrate into vadim
#   j) add arguments
#   k) add/revise help
#   l) add docstrings
#   m) add argument to run arbitrary sql command(s)
#   n) prevent SQL injection attacks ... INSERT (:name, ...)", {'first':<variable, "....}
#      n.1) standardize SQL statements
#      n.2) use something like this (with colons :)
#           cursor.execute("SELECT admin FROM users WHERE username = %(username)s", {'username': username});
#   q) methods to add (INSERT), update (MODIFY), delete (REMOVE) into a table
#   s) remove Friendly Name from data table
#
#   w) add tests to ensure everything works
#   x) run pydoc
#   y) run pylint
#   z) add to github
#
# Do later or not at all (I am tired of working on this):
#
# Won't Do:
#   e) add command to initialize database
#      rm <database_name>.db
#
# Completed:
#   a) create main tables
#      a.1) discover
#      a.2) data
#   d) my ...
#      d.2) raspberry pi projects: https://sites.google.com/site/cartwrightraspberrypiprojects/home/home-automation-categories/lighting/smart-wi-fi-switches-by-room?authuser=0
#   o) use with statement with conn to avoid using commmit
#   p) use CREATE TABLE IF NOT EXISTS <tablename>
#   r) username and timestamp on each change
#
############################# <- 80 Characters -> ##############################

# Built-in Python3 Module
import sys
import datetime
import sqlite3
from sqlite3 import Error

# Modules that must be installed (pip3)

# My Modules (from github)
# pylint reports; C0413: Import "from mylog import MyLog" should be placed at
# the top of the module. However, I am not sure how to fix this issue.
# sys.path.append is required for me to import my module
sys.path.append("..")
from mylog import MyLog

# Global Veriables (FirstUpper or CapWord)

# Global Constants (ALL CAPS)
# database filename, which may include a path to the file
DATABASE_NAME = 'wemo.db'

# Classes
class WemoDB:
    def __init__(self, logger, filename = DATABASE_NAME):
        self.filename = filename
        self.logger = logger

        self.connection = None
        try:
            self.connection = sqlite3.connect(self.filename)
            try:
                self.cursor = self.connection.cursor()
            except Error as e:
                logger.logPrint("ERROR", e)
                sys.exit()
        except Error as e:
            self.logger.logPrint("ERROR", filename + ": " + e)
            sys.exit()

        self.createTableDiscover()
        self.createTableData()

    def createTableDiscover(self):
        ''' The table discover is used to store results of vadim's disacover 
            command. To make the table complete, the data command adds the MAC 
            Address.

            A WeMo device's IP Address is set via DHCP and so it can change. In
            general, a DHCP assigned IP Address should not change beccause the
            lease renewal request occurs 1/2-way before the DHCP lease expires.
            Nevertheless, it can occur.

            A Wemo's port is generally fixed, but it is not unique. The Friendly
            Name does not need to be unique and can also change during set up or
            a reset.

            For most devices, the MAC Address is the only data that cannot 
            change. So, most tables in this database will use the MAC address as
            the primary key.

            However, vadim's discover command only yields: IP address, Friendly
            Name and port, but, no MAC Address. So, the discover command will
            need to be run followed by the data command on each IP Address and
            port to get the MAC Address.
        '''

        cmd = """ CREATE TABLE IF NOT EXISTS discover (
                  MACaddress text,
                  FriendlyName text,
                  IPaddress text,
                  Port text,
                  Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
              ); """
        try:
            self.cursor.execute(cmd)
            # commit is not required after CREATE TABLE command
            # the python module handles the commit
        except Error as e:
            self.logger.logPrint("ERROR", e)
            sys.exit()

    def addRowDiscover(self, friendlyName, ipAddress, port):
        ''' Add a row from vadim's discover command into the discover table.

            Minimize SQL injection by using parameterized names and a dictionary
            for the INSERT

            Don't add duplicate IP addresses

            The MAC Address is left empty since it is unknown after discover
        '''

        currentDateTime = datetime.datetime.now()

        # check for a duplicate IP Address
        dup = ''' SELECT * FROM discover
                  WHERE ipAddress = ?
                  ORDER BY Timestamp DESC'''

        with self.connection:
            # need a comma after ipAddress to make it into a tuple
            self.cursor.execute(dup, (ipAddress,))
            rows = self.cursor.fetchall()
            rowCount = len(rows)
            if rowCount == 0:
                self.cursor.execute("INSERT INTO discover VALUES (:MACaddress, \
                    :FriendlyName, :IPaddress, :Port, :Timestamp)", \
                    {'MACaddress': '', 'FriendlyName': friendlyName, \
                    'IPaddress': ipAddress, 'Port': port, \
                    'Timestamp': currentDateTime})
            elif rowCount == 1:
                # IP Address must be unique
                self.logger.logPrint("DEBUG",
                    "    IP Address = " + ipAddress + " is not unique. Replacing with new data")
                sql = ''' UPDATE discover
                          SET MACaddress = ?,
                              FriendlyName = ?,
                              IPaddress = ?,
                              Port = ?,
                              Timestamp = ?
                          WHERE IPaddress = ? '''
                self.cursor.execute(sql, ('', friendlyName, ipAddress, port, \
                    currentDateTime,  ipAddress,))
            else:
                # The IP Address does not need to be unique, but should not 
                # be duplicated
                self.logger.logPrint("DEBUG",
                    "    Deleting all rows with duplicate IP Addresses = "
                    + ipAddress)
                self.deleteIpAddress(ipAddress)

                self.logger.logPrint("DEBUG",
                    "    Adding data for newest IP Address")
                self.cursor.execute("INSERT INTO discover VALUES (:MACaddress, \
                    :FriendlyName, :IPaddress, :Port, :Timestamp)", \
                    {'MACaddress': '', 'FriendlyName': friendlyName, \
                    'IPaddress': ipAddress, 'Port': port, \
                    'Timestamp': currentDateTime})

    def getDiscover(self):
        ''' Get all the rows in the discover table.

            The primary purpose of this is to add the MAC Address using
            addMacDiscover().
        '''

        with self.connection:
            self.cursor.execute("SELECT * FROM discover")

        rows = self.cursor.fetchall()

        return rows

    def addMacDiscover(self, macAddress, ipAddress, Port):
        ''' Find the row by its IP Address and add its MAC Address

            The IP Address must be unique. If there are duplicate IP 
            Addresses, then the older ones are deleted.
        '''

        # check for a duplicate IP Address
        dup = ''' SELECT * FROM discover 
                  WHERE IPaddress = ? 
                  ORDER BY Timestamp DESC'''

        with self.connection:
            # need a comma after IPaddress to make it into a tuple
            self.cursor.execute(dup, (ipAddress,))
            rows = self.cursor.fetchall()
            rowCount = len(rows)
            if rowCount == 0:
                self.logger.logPrint("INFO", 
                    "No rows in discover table  for IP Address = " + ipAddress)
            elif rowCount == 1:
                # IP Address should be unique
                self.logger.logPrint("DEBUG", "mac = " + macAddress + " ip = "
                    + ipAddress + " port = " + Port)
                sql = ''' UPDATE discover
                          SET MACaddress = ?
                          WHERE IPaddress = ? AND Port = ? '''
                self.cursor.execute(sql, (macAddress, ipAddress, Port))
            else:
                # The IP Address does not need to be unique, but should not
                # be duplicated
                self.logger.logPrint("INFO",
                    "Duplicate IP Addresses found in discover table = ")
                self.logger.logPrint("INFO",
                    "    Deleting all rows with IP Address = "
                    + ipAddress)
                self.deleteIpAddress(ipAddress)
                # ??? not enough arguments to add the ip, fn, mac and port back

    def deleteIpAddress(self, ipAddress):
        """ Delete all rows matching the IP Address from the discover table.
        """

        sql = 'DELETE from data WHERE IPaddress = ? '
        with self.connection:
            # need the extra comma at the end to make it into a tuple
            self.cursor.execute(sql, (ipAddress,))

    def printAllData(self):
        """ Join data and discover tables on macAddress and print the results
        """
        self.logger.logPrint("INFO", "#\tFriendly Name\t\tMAC Address\tIP Address\tPort\tVersion\tSerial Number\tCode\t\tSwitch Type")
        self.logger.logPrint("INFO", "----\t-------------\t\t------------\t---------------\t-----\t-------\t--------------\t----------\t-----------")
        sql = 'SELECT * FROM discover INNER JOIN data ON discover.MACaddress = data.MACaddress'
        self.cursor.execute(sql)
        rows = self.cursor.fetchall()
        r = 1
        for row in rows:
            if len(row[1]) < 8:
                self.logger.logPrint("INFO", str(r) + "\t" + row[1] + "\t\t\t" + row[0] + "\t" + row[2] + "\t" + row[3] + "\t" + row[8] + "\t" + row[9] + "\t" + row[10] + "\t" + row[7])
            elif len(row[1]) < 16:
                self.logger.logPrint("INFO", str(r) + "\t" + row[1] + "\t\t" + row[0] + "\t" + row[2] + "\t" + row[3] + "\t" + row[8] + "\t" + row[9] + "\t" + row[10] + "\t" + row[7])
            else:
                self.logger.logPrint("INFO", str(r) + "\t" + row[1] + "\t" + row[0] + "\t" + row[2] + "\t" + row[3] + "\t" + row[8] + "\t" + row[9] + "\t" + row[10] + "\t" + row[7])
            r += 1
        # ??? I am sure there is a better way to format the output

    def createTableData(self):
        # For most devices, the MAC Address is the only data that cannot change.
        # So, use the MAC address as the primary key.
        #
        # vadim's data command yields: Friendly Name, WeMo model, HW version,
        # serial #, MAC Address and set-up code
        cmd = """ CREATE TABLE IF NOT EXISTS data (
                  MACaddress text PRIMARY KEY,
                  FriendlyName text,
                  ModelName text,
                  HWversion text,
                  SerialNumber text,
                  SetupCode text,
                  Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
              ); """
        try:
            self.cursor.execute(cmd)
            # commit is not required after CREATE TABLE command
            # the python module handles the commit
        except Error as e:
            self.logger.logPrint("ERROR", e)
            sys.exit()

    def addRowData(self, macAddress, friendlyName, modelName, hwVersion, 
        serialNumber, setupCode):
        """ Add a row from vadim's data command into the data table.

            Minimize SQL injection by using parameterized names and a dictionary
            for the INSERT
        """

        currentDateTime = datetime.datetime.now()

        # check for a duplicate MAC Address
        dup = ''' SELECT * FROM data
                  WHERE MACaddress = ?
                  ORDER BY Timestamp DESC'''

        with self.connection:
            # need the extra comma at the end of IPaddress to make it into a tuple
            self.cursor.execute(dup, (macAddress,))
            rows = self.cursor.fetchall()
            rowCount = len(rows)
            if rowCount == 0:
                self.cursor.execute("INSERT INTO data VALUES (:MACaddress, \
                    :FriendlyName, :ModelName, :HWversion, :SerialNumber, \
                    :SetUpCode, :Timestamp)",
                    {'MACaddress': macAddress, 'FriendlyName': friendlyName, \
                    'ModelName': modelName, 'HWversion': hwVersion, \
                    'SerialNumber': serialNumber, 'SetUpCode': setupCode, \
                    'Timestamp': currentDateTime})
            elif rowCount == 1:
                # MAC Address must be unique
                self.logger.logPrint("DEBUG",
                    "    MAC Address = " + macAddress + " is not unique. Replacing with new data.")

                sql = ''' UPDATE data
                          SET FriendlyName = ?,
                              ModelName = ?,
                              HWversion = ?,
                              SerialNumber = ?,
                              SetUpCode = ?,
                              Timestamp = ?
                          WHERE MACaddress = ? '''
                self.cursor.execute(sql, (friendlyName, modelName, hwVersion, \
                    serialNumber, setupCode, currentDateTime,  macAddress,))
            else:
                # table requires MACaddress to be unique. So, this chunk of code
                # should never execute
                self.logger.logPrint("DEBUG",
                    "    Deleting all rows with multiple MAC Addresses = "
                    + macAddress)
                self.deleteMacAddress(macAddress)

                self.logger.logPrint("DEBUG",
                    "    Adding data for newest MAC Address = "
                    + macAddress)
                self.cursor.execute("INSERT INTO data VALUES (:MACaddress, \
                    :FriendlyName, :ModelName, :HWversion, :SerialNumber, \
                    :SetUpCode, :Timestamp)",
                    {'MACaddress': macAddress, 'FriendlyName': friendlyName, \
                    'ModelName': modelName, 'HWversion': hwVersion, \
                    'SerialNumber': serialNumber, 'SetUpCode': setupCode, \
                    'Timestamp': currentDateTime})

    def deleteMacAddress(self, macAddress):
        """ Delete all rows matching the MAC Address from the data table.
        """

        sql = 'DELETE from data WHERE MACaddress = ? '
        with self.connection:
            # need the extra comma at the end to make it into a tuple
            self.cursor.execute(sql, (macAddress,))

    # ??? def createTableFailures(self):
        # MAC-Address, failureType, Description, timeStamp

    # ??? create table to Excel data

    def	initializeWemoDB(self):
        self.cursor.execute("SELECT COUNT(*) from data")
        (rows,) = self.cursor.fetchone()
        if rows == 0:
            self.logger.logPrint("DEBUG", "no rows found in table: wemo")
        # ??? do for each table

class MyLogArguments:
    """ 
    To run wemo-db.py as a stand-alone script, then command line 
    arguments are required to exercise and test its features.
    """

    def __init__(self):
        self.parser = argparse.ArgumentParser(description='script 1.0')

        # for each argument add
        self.parser.add_argument('-c', '--count', help='log rotate count')
        self.parser.add_argument('-f', '--filename', help='log filename')
        self.parser.add_argument('-l', '--level', help='logging level = NOTSET, INFO, DEBUG, WARNING, ERROR, CRITIICAL')
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
    WemoDB -- WemoDB adds sqlite3 to vadim.py to store data about WeMo devices
        in my house.

\033[1mSYNOPSIS\033[0m
    Run as a script:
        python3 wemo-db.py [-options]

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
    WemoDB is used as a module to provide sqlite3 database features for 
    vadim.py.

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
        $ pydoc ./wemo-db.py

''')
        # exit doesn't go here



# function definitions
def main(logger):
    db = WemoDB(DATABASE_NAME)

    db.initializeWemoDB()

# In every script, ALWAYS use an if main
if __name__ == "__main__":
    logger = MyLog()
    logger.setLevel("DEBUG")
    logger.setOutput("CONSOLE")
    logger.openOutput()

    main(logger)

