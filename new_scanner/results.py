import ipaddress

import MySQLdb
import _mysql_exceptions

def get_target_from_SQL(table_name="scanner_side_record") -> [str,]:
    connection = MySQLdb.connect(
        "localhost", 
        "root", 
        "", 
        "dns_scan_records"
    )
    cursor = connection.cursor()

    try:
        cursor.execute(
            ("SELECT response_time FROM {} "
            "WHERE response_status='ok'".format(table_name))
        )
        data = cursor.fetchall()
        connection.close()
        return data

    except Exception as e:
        print(e)
        return None


