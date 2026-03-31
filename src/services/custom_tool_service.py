"""
┌──────────────────────────────────────────────────────────────────────────────┐
│ @author: Davidson Gomes                                                      │
│ @file: custom_tool_service.py                                               │
│ Developed by: Davidson Gomes                                                 │
│ Creation date: January 14, 2025                                              │
│ Contact: contato@evolution-api.com                                           │
├──────────────────────────────────────────────────────────────────────────────┤
│ @copyright © Evolution API 2025. All rights reserved.                        │
│ Licensed under the Apache License, Version 2.0                               │
│                                                                              │
│ You may not use this file except in compliance with the License.             │
│ You may obtain a copy of the License at                                      │
│                                                                              │
│    http://www.apache.org/licenses/LICENSE-2.0                                │
│                                                                              │
│ Unless required by applicable law or agreed to in writing, software          │
│ distributed under the License is distributed on an "AS IS" BASIS,            │
│ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.     │
│ See the License for the specific language governing permissions and          │
│ limitations under the License.                                               │
├──────────────────────────────────────────────────────────────────────────────┤
│ @important                                                                   │
│ For any future changes to the code in this file, it is recommended to        │
│ include, together with the modification, the information of the developer    │
│ who changed it and the date of modification.                                 │
└──────────────────────────────────────────────────────────────────────────────┘
"""

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from src.schemas.schemas import CustomTool
from typing import List, Optional, Dict, Any
import logging
logger = logging.getLogger(__name__)

# Fetch custom tools with optional filtering
async def get_custom_tools(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    search: Optional[str] = None,
    tags: Optional[List[str]] = None,
) -> List[CustomTool]:
    """Get custom tools with filtering"""

    try:
        query = db.query(CustomTool)

        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                CustomTool.name.ilike(search_filter)
                | CustomTool.description.ilike(search_filter)
            )

        if tags:
            # Filter by tags (JSON contains)
            for tag in tags:
                query = query.filter(CustomTool.tags.contains([tag]))

        return query.order_by(CustomTool.name).offset(skip).limit(limit).all()
    except SQLAlchemyError as e:
        logger.error(f"Error getting custom tools: {str(e)}")
        return []

# Convert CustomTool to HTTPTool format for agent configuration 
def convert_to_http_tool(custom_tool: CustomTool) -> Dict[str, Any]:
    """Convert CustomTool to HTTPTool format for agent configuration"""
    # Ensure error_handling has all required fields with defaults
    error_handling = custom_tool.error_handling or {}
    default_error_handling = {
        "timeout": error_handling.get("timeout", 30),
        "retry_count": error_handling.get("retry_count", 0),
        "fallback_response": error_handling.get(
            "fallback_response", {"error": "", "message": ""}
        ),
    }

    return {
        "name": custom_tool.name,
        "method": custom_tool.method,
        "endpoint": custom_tool.endpoint,
        "headers": custom_tool.headers,
        "parameters": {
            "path_params": custom_tool.path_params,
            "query_params": custom_tool.query_params,
            "body_params": custom_tool.body_params,
        },
        "description": custom_tool.description or "",
        "error_handling": default_error_handling,
        "values": custom_tool.values,
    }

