import mysql.connector

# Connect to MySQL
connection = mysql.connector.connect(
    host="localhost",
    user="root",  # Replace with your MySQL username
    password="xybp56mr",  # Replace with your MySQL root password
    database="port_scanner_db"
)

if connection.is_connected():
    print("Connected to MySQL successfully!")
else:
    print("Connection failed!")

connection.close()
