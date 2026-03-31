"""Google Sheets append tool."""

from typing import Optional, Dict, Any, List
from google.adk.tools import FunctionTool, ToolContext
import traceback

from .base import GoogleSheetsClient
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def create_append_spreadsheet_tool(
    agent_id: Optional[str] = None,
    sheets_config: Optional[Dict[str, Any]] = None,
    credentials_config: Optional[Dict[str, Any]] = None,
    db=None
) -> FunctionTool:
    """
    Create a tool for appending data to Google Sheets spreadsheets.

    Args:
        agent_id: Optional default agent ID
        sheets_config: Google Sheets configuration from agent.config.integrations
        credentials_config: Google Sheets credentials from agent.config.integrations
        db: Database session for direct database access

    Returns:
        FunctionTool for appending spreadsheet data
    """
    client = GoogleSheetsClient(db=db)

    async def append_spreadsheet(
        spreadsheet_id: str,
        range_name: str,
        values: List[List[Any]],
        tool_context: Optional[ToolContext] = None,
    ) -> Dict[str, Any]:
        """
        Append data to a Google Sheets spreadsheet.

        This tool adds new rows to a spreadsheet without replacing existing content.
        The data will be appended after the last row with data in the specified range.

        Use this tool when:
        - You need to add new records to a spreadsheet
        - You're logging data or events
        - You want to add rows without affecting existing data
        - You're collecting form responses or customer information

        The tool will:
        - Find the last row with data
        - Append your new rows after it
        - Preserve all existing content
        - Return the range where data was added

        Args:
            spreadsheet_id: The ID of the spreadsheet to append to (found in the URL)
            range_name: The range to append to (e.g., 'Sheet1!A1' or 'Data!A:E')
            values: 2D array of values to append [[row1], [row2], ...]
            tool_context: Tool execution context

        Returns:
            Dictionary with append results or error message
        """
        try:
            logger.info(f"Appending to Google Sheets spreadsheet: {spreadsheet_id}, range: {range_name}")

            # Use agent_id from closure
            effective_agent_id = agent_id

            # Validate required parameters
            if not effective_agent_id:
                return {
                    "status": "error",
                    "message": "Agent ID is required but was not provided"
                }

            # Validate configs provided
            if not credentials_config:
                return {
                    "status": "error",
                    "message": "Google Sheets credentials not configured for this agent"
                }

            if not spreadsheet_id or not spreadsheet_id.strip():
                return {
                    "status": "error",
                    "message": "Spreadsheet ID is required"
                }

            if not range_name or not range_name.strip():
                return {
                    "status": "error",
                    "message": "Range name is required"
                }

            if not values or not isinstance(values, list):
                return {
                    "status": "error",
                    "message": "Values must be a 2D array (list of lists)"
                }

            # Validate values structure
            if not all(isinstance(row, list) for row in values):
                return {
                    "status": "error",
                    "message": "Each row in values must be a list"
                }

            # Append to the spreadsheet
            logger.info(f"Appending {len(values)} rows to Google Sheets")
            result = await client.append_spreadsheet(
                credentials_config=credentials_config,
                spreadsheet_id=spreadsheet_id,
                range_name=range_name,
                values=values
            )

            if result["status"] == "error":
                logger.error(f"Append failed: {result.get('message')}")
                return result

            # Build success response
            response = {
                "status": "success",
                "message": result.get("message", "Data appended successfully"),
                "details": {
                    "updated_cells": result.get("updated_cells", 0),
                    "updated_range": result.get("updated_range", ""),
                    "updated_rows": result.get("updated_rows", 0),
                    "updated_columns": result.get("updated_columns", 0)
                }
            }

            logger.info(f"Successfully appended {result.get('updated_rows', 0)} rows")
            return response

        except Exception as e:
            logger.error(f"Unexpected error in append_spreadsheet: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "status": "error",
                "message": f"Failed to append to spreadsheet: {str(e)}"
            }

    # Set function metadata
    append_spreadsheet.__name__ = "append_spreadsheet"

    append_spreadsheet.__doc__ = """Append data to a Google Sheets spreadsheet without replacing existing content.

Use this tool to add new rows to a spreadsheet. The data will be added after the last row that
contains data, preserving all existing content.

Args:
    spreadsheet_id (str): The spreadsheet ID (found in the spreadsheet URL after /d/)
    range_name (str): The range to append to (usually just the sheet name or starting column)
                     Examples: 'Sheet1!A:E', 'Data!A1', 'Logs!A:Z'
    values (list): 2D array of values to append, e.g., [['John', 'john@example.com'], ['Jane', 'jane@example.com']]

Returns:
    Dictionary containing:
    - message: Success message
    - updated_cells: Number of cells added
    - updated_range: The actual range where data was appended
    - updated_rows: Number of rows added
    - updated_columns: Number of columns added

Examples:
- Add new customer: spreadsheet_id='abc123', range_name='Customers!A:C',
                   values=[['John Doe', 'john@example.com', '555-0100']]
- Log event: spreadsheet_id='abc123', range_name='Logs!A1',
            values=[['2024-01-15', 'User login', 'john@example.com']]
- Add multiple records: spreadsheet_id='abc123', range_name='Sheet1!A:E',
                       values=[['Alice', 25, 'NY'], ['Bob', 30, 'CA']]

Note: This will NOT replace existing content. To update existing data, use write_spreadsheet instead.
"""

    return FunctionTool(func=append_spreadsheet)
