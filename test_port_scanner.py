import unittest
from unittest.mock import patch
from port_scanner import PortScannerApp

class TestPortScannerApp(unittest.TestCase):

    @patch('port_scanner.mysql.connector.connect')
    def test_save_to_database(self, mock_db):
        # Mock the database connection and cursor
        mock_cursor = mock_db.return_value.cursor.return_value

        # Call the save_to_database method
        PortScannerApp.save_to_database("192.168.1.1", [22, 80])

        # Verify that the database insert was called correctly
        mock_cursor.execute.assert_called_with(
            "INSERT INTO scans (ip_address, port, status) VALUES (%s, %s, %s)",
            ("192.168.1.1", 80, "open")
        )
        mock_db.return_value.commit.assert_called_once()

    def test_save_to_file(self):
        # Call the save_to_file method
        PortScannerApp.save_to_file("192.168.1.1", [22, 80])

        # Verify the file content
        with open("scan_results.txt", "r") as file:
            content = file.read()
            self.assertIn("Scan Result for 192.168.1.1:", content)
            self.assertIn("Open Ports: 22, 80", content)

if __name__ == "__main__":
    # Prevent unittest.main() from exiting the program
    unittest.main(exit=False)
    