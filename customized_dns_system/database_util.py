import MySQLdb
import _mysql_exceptions

from config import *

class CursorProvider(object):
    def __init__(self):
        self.__database_handle = MySQLdb.connect(
        "localhost", 
        "root", 
        "", 
        "dns_scan_records"
    )
        self.__database_handle.autocommit(True)

    def get_cursor(self, table_name):
        return self.__database_handle

    def __del__(self):
        self.__database_handle.close()
