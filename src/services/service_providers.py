"""
┌──────────────────────────────────────────────────────────────────────────────┐
│ @author: Davidson Gomes                                                      │
│ @file: service_providers.py                                                  │
│ Developed by: Davidson Gomes                                                 │
│ Creation date: May 13, 2025                                                  │
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

import os
from google.adk.sessions import DatabaseSessionService
from dotenv import load_dotenv

load_dotenv()

from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def get_async_db_url(db_url: str) -> str:
    """Convert PostgreSQL connection string to async format (postgresql+asyncpg://).
    
    Args:
        db_url: PostgreSQL connection string (postgresql://...)
        
    Returns:
        Async PostgreSQL connection string (postgresql+asyncpg://...)
    """
    if db_url.startswith("postgresql://"):
        return db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif db_url.startswith("postgresql+asyncpg://"):
        return db_url
    else:
        # If already in async format or other format, return as is
        return db_url


# Initialize session service based on AI engine
# DatabaseSessionService requires async driver (asyncpg)
db_url = os.getenv("POSTGRES_CONNECTION_STRING")
async_db_url = get_async_db_url(db_url) if db_url else None
session_service = DatabaseSessionService(db_url=async_db_url)


# Initialize artifacts service using the factory
from src.services.adk.artifacts.artifact_factory import get_artifact_service

artifacts_service = get_artifact_service()
logger.info(
    f"Initialized artifacts service: {type(artifacts_service).__name__} from module: {type(artifacts_service).__module__}"
)


# Initialize memory service with retention limits
from src.services.memory_service import memory_service
