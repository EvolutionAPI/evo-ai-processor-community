"""Google Sheets read tool."""

from typing import Optional, Dict, Any
from google.adk.tools import FunctionTool, ToolContext
import traceback

from .base import GoogleSheetsClient
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def create_read_spreadsheet_tool(
    agent_id: Optional[str] = None,
    sheets_config: Optional[Dict[str, Any]] = None,
    credentials_config: Optional[Dict[str, Any]] = None,
    db=None
) -> FunctionTool:
    """
    Create a tool for reading data from Google Sheets spreadsheets.

    Args:
        agent_id: Optional default agent ID
        sheets_config: Google Sheets configuration from agent.config.integrations
        credentials_config: Google Sheets credentials from agent.config.integrations
        db: Database session for direct database access

    Returns:
        FunctionTool for reading spreadsheet data
    """
    client = GoogleSheetsClient(db=db)

    async def read_spreadsheet(
        spreadsheet_id: str,
        range_name: str = 'A1:Z1000',
        tool_context: Optional[ToolContext] = None,
    ) -> Dict[str, Any]:
        """
        Read data from a Google Sheets spreadsheet.

        This tool retrieves data from a spreadsheet, returning it as a structured format
        that you can analyze, summarize, or process further.

        Use this tool when:
        - You need to fetch data from a spreadsheet
        - A customer asks about information stored in a spreadsheet
        - You need to analyze or report on spreadsheet data
        - You want to verify existing data before making changes

        The tool will return:
        - All values in the specified range
        - Row and column counts
        - The actual range that was read

        Args:
            spreadsheet_id: The ID of the spreadsheet to read from (found in the URL)
            range_name: The range to read (e.g., 'Sheet1!A1:D10' or 'A1:Z1000')
            tool_context: Tool execution context

        Returns:
            Dictionary with spreadsheet data or error message
        """
        try:
            logger.info(f"Reading Google Sheets spreadsheet: {spreadsheet_id}, range: {range_name}")

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

            # Read the spreadsheet
            logger.info(f"Fetching data from Google Sheets")
            result = await client.read_spreadsheet(
                credentials_config=credentials_config,
                spreadsheet_id=spreadsheet_id,
                range_name=range_name
            )

            if result["status"] == "error":
                logger.error(f"Read failed: {result.get('message')}")
                return result

            # Build success response
            response = {
                "status": "success",
                "message": f"Successfully read {result.get('row_count', 0)} rows from spreadsheet",
                "data": {
                    "values": result.get("values", []),
                    "range": result.get("range", ""),
                    "row_count": result.get("row_count", 0),
                    "column_count": result.get("column_count", 0)
                }
            }

            logger.info(f"Successfully read {result.get('row_count', 0)} rows")
            return response

        except Exception as e:
            logger.error(f"Unexpected error in read_spreadsheet: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "status": "error",
                "message": f"Failed to read spreadsheet: {str(e)}"
            }

    # Set function metadata
    read_spreadsheet.__name__ = "read_spreadsheet"

    read_spreadsheet.__doc__ = """Read data from a Google Sheets spreadsheet.

Use this tool to retrieve data from spreadsheets. The spreadsheet must be already configured in the agent's Google Sheets integration.

Args:
    spreadsheet_id (str): The spreadsheet ID (found in the spreadsheet URL after /d/)
    range_name (str, optional): The range to read in A1 notation (default: 'A1:Z1000')
                                Examples: 'Sheet1!A1:D10', 'Data!A:E', 'A1:Z1000'

Returns:
    Dictionary containing:
    - values: 2D array of cell values
    - range: The actual range that was read
    - row_count: Number of rows read
    - column_count: Number of columns in first row

Examples:
- Read first 1000 rows: spreadsheet_id='abc123', range_name='A1:Z1000'
- Read specific sheet: spreadsheet_id='abc123', range_name='Customers!A1:E100'
- Read all columns: spreadsheet_id='abc123', range_name='Sheet1!A:Z'
- Read specific range: spreadsheet_id='abc123', range_name='B2:D50'

Note: The spreadsheet ID can be found in the URL:
https://docs.google.com/spreadsheets/d/[SPREADSHEET_ID]/edit
"""

    return FunctionTool(func=read_spreadsheet)
