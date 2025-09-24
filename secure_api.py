"""
Secure API implementation that fixes the original security vulnerabilities.

This file demonstrates the security fixes for:
1. Refactored process_everything function with proper separation of concerns
2. SQL injection vulnerability fix using parameterized queries
3. Hardcoded credentials replaced with environment variable configuration
"""

import os
import json
import xml.etree.ElementTree as ET
import re
import hashlib
import base64
import datetime
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SecureConfig:
    """Configuration class that loads sensitive data from environment variables."""
    ldap_server: str
    ldap_user: str
    ldap_password: str
    sql_connection_string: str
    api_key: str
    secret_key: str
    encryption_key: str
    admin_password: str
    backup_urls: List[str]

    @classmethod
    def from_environment(cls) -> 'SecureConfig':
        """Load configuration from environment variables with secure defaults."""
        return cls(
            ldap_server=os.getenv("LDAP_SERVER", "ldap://localhost:389"),
            ldap_user=os.getenv("LDAP_USER", "admin"),
            ldap_password=os.getenv("LDAP_PASSWORD", ""),
            sql_connection_string=os.getenv("SQL_CONNECTION_STRING", ""),
            api_key=os.getenv("API_KEY", ""),
            secret_key=os.getenv("SECRET_KEY", ""),
            encryption_key=os.getenv("ENCRYPTION_KEY", ""),
            admin_password=os.getenv("ADMIN_PASSWORD", ""),
            backup_urls=os.getenv("BACKUP_URLS", "").split(",") if os.getenv("BACKUP_URLS") else []
        )

class DataParser:
    """Handles data parsing operations."""

    @staticmethod
    def parse_json_data(data: str) -> Optional[Dict[str, Any]]:
        """Parse JSON data with error handling."""
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {str(e)}")
            return None

    @staticmethod
    def parse_xml_data(data: str) -> Optional[Dict[str, Any]]:
        """Parse XML data with error handling."""
        try:
            root = ET.fromstring(data)
            return {child.tag: child.text for child in root}
        except ET.ParseError as e:
            logger.error(f"XML parse error: {str(e)}")
            return None

class DatabaseService:
    """Secure database service with parameterized queries."""

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.connection = None
        self.errors = []

    def connect(self) -> bool:
        """Establish database connection."""
        if not self.connection_string:
            logger.error("Database connection string not configured")
            return False
        
        try:
            import pyodbc
            self.connection = pyodbc.connect(self.connection_string)
            return True
        except ImportError:
            logger.warning("pyodbc module not available - database operations disabled")
            return False
        except Exception as e:
            error_msg = f"Database connection error: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False

    def save_to_database(self, data: List[Dict[str, Any]]) -> bool:
        """
        Save data using parameterized queries to prevent SQL injection.
        
        SECURITY FIX: Replaced string formatting with parameterized queries.
        """
        if not self.connect():
            return False

        if not data:
            logger.info("No data to save")
            return True

        try:
            cursor = self.connection.cursor()
            
            # Use parameterized query to prevent SQL injection
            query = """
            INSERT INTO users (id, name, email, phone, created_date, email_valid, phone_valid)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            
            for record in data:
                # Use parameter substitution instead of string formatting
                cursor.execute(query, (
                    record.get('id', ''),
                    record.get('name', ''),
                    record.get('email', ''),
                    record.get('phone', ''),
                    record.get('created_date', ''),
                    bool(record.get('email_valid', False)),
                    bool(record.get('phone_valid', False))
                ))
            
            self.connection.commit()
            logger.info(f"Successfully saved {len(data)} records to database")
            return True
            
        except Exception as e:
            error_msg = f"Database save error: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            
            # Rollback transaction on error
            if self.connection:
                try:
                    self.connection.rollback()
                except:
                    pass
            return False

    def close(self):
        """Close database connection."""
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
            finally:
                self.connection = None

class FileService:
    """Handles file operations."""

    def __init__(self):
        self.temp_files = []
        self.errors = []

    def save_to_file(self, filename: str, data: List[Dict[str, Any]], format: str = 'json') -> bool:
        """Save data to file in specified format."""
        try:
            if format == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            elif format == 'xml':
                root = ET.Element("data")
                for item in data:
                    record = ET.SubElement(root, "record")
                    for key, value in item.items():
                        elem = ET.SubElement(record, key)
                        elem.text = str(value) if value is not None else ""
                tree = ET.ElementTree(root)
                tree.write(filename, encoding='utf-8', xml_declaration=True)
            
            self.temp_files.append(filename)
            logger.info(f"Data saved to file: {filename}")
            return True
            
        except Exception as e:
            error_msg = f"File save error: {str(e)}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return False

    def cleanup_temp_files(self):
        """Clean up temporary files."""
        for filename in self.temp_files:
            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except Exception as e:
                logger.error(f"Failed to remove temp file {filename}: {str(e)}")
        self.temp_files.clear()

class BackupService:
    """Handles data backup operations."""

    def __init__(self, backup_urls: List[str]):
        self.backup_urls = backup_urls
        self.errors = []

    def backup_data(self, data: List[Dict[str, Any]]) -> bool:
        """Backup data to configured endpoints."""
        if not self.backup_urls:
            logger.info("No backup URLs configured")
            return True

        success = False
        for url in self.backup_urls:
            try:
                # In a real implementation, you would make HTTP requests to backup endpoints
                # This is a mock implementation for security demonstration
                logger.info(f"Backing up data to: {url}")
                success = True
            except Exception as e:
                error_msg = f"Backup error for {url}: {str(e)}"
                logger.error(error_msg)
                self.errors.append(error_msg)
        
        return success

class SecureAPI:
    """
    Secure API implementation with refactored process_everything method.
    
    SECURITY FIXES IMPLEMENTED:
    1. Configuration loaded from environment variables instead of hardcoded values
    2. SQL injection vulnerability fixed with parameterized queries
    3. Separation of concerns with dedicated service classes
    4. Proper error handling and logging
    """

    def __init__(self):
        self.config = SecureConfig.from_environment()
        self.parser = DataParser()
        self.database_service = DatabaseService(self.config.sql_connection_string)
        self.file_service = FileService()
        self.backup_service = BackupService(self.config.backup_urls)
        
        self.data = []
        self.processed_data = []
        self.errors = []
        self.logs = []

    def validate_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and clean data."""
        # Add validation logic here
        validated_data = {}
        
        # Basic validation example
        validated_data['id'] = str(data.get('id', ''))
        validated_data['name'] = str(data.get('name', ''))
        validated_data['email'] = str(data.get('email', ''))
        validated_data['phone'] = str(data.get('phone', ''))
        validated_data['created_date'] = str(data.get('created_date', datetime.datetime.now().isoformat()))
        validated_data['email_valid'] = bool(data.get('email_valid', False))
        validated_data['phone_valid'] = bool(data.get('phone_valid', False))
        
        return validated_data

    def parse_input_data(self, input_data: List[Any]) -> List[Dict[str, Any]]:
        """
        Parse input data from various formats.
        
        REFACTORING: Extracted from process_everything for better separation of concerns.
        """
        parsed_data = []
        
        for item in input_data:
            if isinstance(item, str):
                if item.startswith('{') or item.startswith('['):
                    parsed = self.parser.parse_json_data(item)
                elif item.startswith('<'):
                    parsed = self.parser.parse_xml_data(item)
                else:
                    logger.warning(f"Unsupported string format: {item[:50]}...")
                    continue
            elif isinstance(item, dict):
                parsed = item
            else:
                logger.warning(f"Unsupported data type: {type(item)}")
                continue

            if parsed:
                parsed_data.append(parsed)
        
        return parsed_data

    def validate_and_process_data(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate and process parsed data.
        
        REFACTORING: Extracted from process_everything for better separation of concerns.
        """
        processed_data = []
        
        for data in data_list:
            try:
                validated = self.validate_data(data)
                if validated:
                    processed_data.append(validated)
            except Exception as e:
                error_msg = f"Data validation error: {str(e)}"
                logger.error(error_msg)
                self.errors.append(error_msg)
        
        return processed_data

    def generate_report(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate processing report."""
        return {
            'total_records': len(data),
            'timestamp': datetime.datetime.now().isoformat(),
            'errors_count': len(self.errors),
            'has_email_validation': any(record.get('email_valid') for record in data),
            'has_phone_validation': any(record.get('phone_valid') for record in data)
        }

    def log_activity(self, activity_type: str, message: str):
        """Log activity with timestamp."""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'type': activity_type,
            'message': message
        }
        self.logs.append(log_entry)
        logger.info(f"{activity_type}: {message}")

    def process_everything(self, input_data: List[Any], output_file: Optional[str] = None, backup: bool = True) -> Dict[str, Any]:
        """
        REFACTORED: Main processing method with improved structure and security.
        
        IMPROVEMENTS:
        1. Separation of concerns - parsing, validation, and processing are separate methods
        2. Better error handling with specific error messages
        3. Proper logging throughout the process
        4. Type hints for better code documentation
        5. Early returns to reduce nesting
        6. Uses secure services that prevent SQL injection
        """
        self.log_activity("PROCESS_START", "Starting secure data processing pipeline")
        
        # Reset errors for this processing run
        self.errors.clear()
        
        # Step 1: Parse input data
        parsed_data = self.parse_input_data(input_data)
        if not parsed_data:
            self.log_activity("PROCESS_ERROR", "No valid data found in input")
            return {
                'success': False,
                'processed_count': 0,
                'errors': self.errors
            }

        # Step 2: Validate and process data
        processed_data = self.validate_and_process_data(parsed_data)
        if not processed_data:
            self.log_activity("PROCESS_ERROR", "No data passed validation")
            return {
                'success': False,
                'processed_count': 0,
                'errors': self.errors
            }

        self.processed_data = processed_data

        # Step 3: Save to database (with SQL injection protection)
        database_success = self.database_service.save_to_database(processed_data)
        if not database_success:
            self.errors.extend(self.database_service.errors)

        # Step 4: Save to file if requested
        if output_file:
            file_success = self.file_service.save_to_file(output_file, processed_data)
            if not file_success:
                self.errors.extend(self.file_service.errors)

        # Step 5: Backup data if requested
        if backup:
            backup_success = self.backup_service.backup_data(processed_data)
            if not backup_success:
                self.errors.extend(self.backup_service.errors)

        # Step 6: Generate report
        report = self.generate_report(processed_data)
        
        self.log_activity("PROCESS_COMPLETE", f"Successfully processed {len(processed_data)} records")

        return {
            'success': True,
            'processed_count': len(processed_data),
            'report': report,
            'errors': self.errors
        }

    def cleanup(self):
        """Clean up resources and temporary files."""
        try:
            self.file_service.cleanup_temp_files()
            self.database_service.close()
            logger.info("Cleanup completed successfully")
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with automatic cleanup."""
        self.cleanup()

# Example usage demonstrating secure configuration
if __name__ == "__main__":
    # Example of setting environment variables for security
    os.environ.setdefault("LDAP_SERVER", "ldap://secure-ldap.company.com:389")
    os.environ.setdefault("LDAP_USER", "service_account")
    os.environ.setdefault("LDAP_PASSWORD", "secure_password_from_vault")
    os.environ.setdefault("SQL_CONNECTION_STRING", "DRIVER={ODBC Driver 17 for SQL Server};SERVER=secure-db.company.com;DATABASE=ProductionDB;UID=service_user;PWD=secure_db_password")
    os.environ.setdefault("API_KEY", "secure-api-key-from-vault")
    os.environ.setdefault("SECRET_KEY", "secure-secret-key-from-vault")
    os.environ.setdefault("ENCRYPTION_KEY", "secure-encryption-key-from-vault")
    os.environ.setdefault("ADMIN_PASSWORD", "secure-admin-password-from-vault")
    os.environ.setdefault("BACKUP_URLS", "https://backup1.company.com/api,https://backup2.company.com/api")

    # Example usage with context manager for automatic cleanup
    with SecureAPI() as api:
        sample_data = [
            '{"id": "1", "name": "John Doe", "email": "john@example.com"}',
            '{"id": "2", "name": "Jane Smith", "email": "jane@example.com"}'
        ]
        
        result = api.process_everything(
            input_data=sample_data,
            output_file="output.json",
            backup=True
        )
        
        print(f"Processing result: {result}")
