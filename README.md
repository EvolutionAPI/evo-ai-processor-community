<h1 align="center">Evo AI - Agent Processor</h1>

<div align="center">

[![Whatsapp Group](https://img.shields.io/badge/Group-WhatsApp-%2322BC18)](https://evolution-api.com/whatsapp)
[![Discord Community](https://img.shields.io/badge/Discord-Community-blue)](https://evolution-api.com/discord)
[![Postman Collection](https://img.shields.io/badge/Postman-Collection-orange)](https://evolution-api.com/postman)
[![Documentation](https://img.shields.io/badge/Documentation-Official-green)](https://doc.evolution-api.com)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![Support](https://img.shields.io/badge/Donation-picpay-green)](https://app.picpay.com/user/davidsongomes1998)
[![Sponsors](https://img.shields.io/badge/Github-sponsor-orange)](https://github.com/sponsors/EvolutionAPI)

</div>

## Overview

Evo AI Agent Processor is the core microservice of the Evo AI platform, responsible for orchestrating intelligent workflows between multiple agents, processing sessions, storing and searching knowledge in vector databases, and integrating with modern AI services. It provides:

- Workflow orchestration between agents using LangGraph
- Execution of ADK agents (Google ADK) and integration with Google GenAI
- Session, event, and artifact processing
- Knowledge search and storage in vector databases (Pinecone, Qdrant, OpenSearch)
- JWT authentication for protected endpoints
- Redis caching for performance
- OpenAI integration for embeddings (optional)
- RESTful API with FastAPI

## Technologies

- **FastAPI**: Web framework for building the API
- **SQLAlchemy**: ORM for database interaction
- **PostgreSQL**: Main database
- **Pydantic**: Data validation
- **Uvicorn**: ASGI server
- **Redis**: Cache and queues
- **JWT (python-jose, pyjwt)**: Authentication and authorization
- **Pinecone / Qdrant / OpenSearch**: Vector databases for semantic search
- **OpenAI**: Embeddings and LLMs (optional)
- **Google ADK**: Execution and management of Google agents
- **LangGraph**: Workflow orchestration between agents
- **MinIO**: Artifact storage
- **Opentelemetry**: Observability and tracing
- **a2a-sdk, mcp**: Integrations and extensions for agents
- **Alembic**: Database schema migration tool for SQLAlchemy

## Prerequisites

- **Python**: 3.10 or higher
- **PostgreSQL**: 13.0 or higher
- **Redis**: 6.0 or higher
- **Git**: For version control
- **Make**: For running Makefile commands

## 🔧 Installation

1. Clone the repository:

```bash
git clone https://github.com/EvolutionAPI/evo-ai-agent-processor.git
cd evo-ai-agent-processor
```

2. Create a virtual environment and install dependencies:

```bash
make venv
source venv/bin/activate  # Linux/Mac
make install-dev  # For development dependencies
```

3. Set up environment variables:

```bash
cp .env.example .env
# Edit the .env file with your settings
```

## Running the Service

```bash
make run         # Development
make run-prod    # Production
```

The API will be available at `http://localhost:8000`

## 👨‍💻 Development Commands

```bash
# Code verification
make lint                      # Verify code with flake8
make format                    # Format code with black

# Cache management
make clear-cache               # Clean basic cache files
make clear-python-cache        # Clean Python cache files (.pyc, __pycache__)
make clear-uv-cache           # Clean UV package manager cache
make clear-all-cache          # Clean all caches (comprehensive)

# Environment management
make reset-venv               # Reset virtual environment
make refresh-env              # Reset environment and reinstall dependencies
```

### 🧹 Cache Management

When you encounter issues with cached environment variables or Python imports, use these commands:

- **`make clear-python-cache`**: Removes Python bytecode files and `__pycache__` directories
- **`make clear-uv-cache`**: Cleans UV package manager cache
- **`make clear-all-cache`**: Comprehensive cache cleanup including system cache
- **`make reset-venv`**: Recreates the virtual environment
- **`make refresh-env`**: Complete environment refresh (recommended for persistent issues)

## 🐳 Running with Docker

1. Configure the `.env` file
2. Start the services:

```bash
make docker-build
make docker-up
make docker-seed
```

## 🤝 Contributing

We welcome contributions from the community! Please read our [Contributing Guidelines](CONTRIBUTING.md) for more details.

## 📄 License

This project is licensed under the [Apache License 2.0](./LICENSE).
