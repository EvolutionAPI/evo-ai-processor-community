"""
┌──────────────────────────────────────────────────────────────────────────────┐
│ @author: Davidson Gomes                                                      │
│ @file: custom_tools.py                                                       │
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

from typing import Any, Callable, Dict, List, Optional
from google.adk.tools import FunctionTool
from google.adk.tools.tool_context import ToolContext
import inspect
import keyword
import requests
import json
import urllib.parse
from src.utils.logger import setup_logger
from src.utils.schema_utils import map_json_type_to_python

logger = setup_logger(__name__)

# The Custom Tools wizard parks the "what it receives / what it returns"
# descriptions inside `values` under a reserved key. It is documentation, never
# a request parameter — it must not reach the wire as a query param or a body
# field. `__modes_meta__` is the legacy spelling.
MODES_META_KEYS = frozenset({"__evo_modes_meta__", "__modes_meta__"})


def strip_modes_meta(values: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Drop the reserved documentation keys from a tool's default values."""
    return {
        key: value
        for key, value in (values or {}).items()
        if key not in MODES_META_KEYS
    }


# ADK fills parameters carrying these names itself, so a tool must never
# declare one of its own.
ADK_RESERVED_PARAM_NAMES = frozenset({"tool_context", "input_stream"})


def _json_type_name(value: Any, default: str = "string") -> str:
    """A usable JSON type name out of an unvalidated configuration value.

    Parameter configs are free-form persisted JSON, so a type can arrive as a
    list, a number or anything else. Falling back to the default keeps one bad
    row from taking the whole agent build down with it.
    """
    if isinstance(value, str) and value.strip():
        return value
    if value is not None:
        logger.warning(
            f"Unusable parameter type {value!r} in tool configuration: "
            f"assuming '{default}'"
        )
    return default


def _param_config(value: Any) -> Dict[str, Any]:
    """A parameter's configuration, whatever the persisted JSON actually holds."""
    return value if isinstance(value, dict) else {}


def _http_tool_element_annotation(element_type: Optional[str] = None) -> Any:
    """Annotation ADK should advertise for the elements of an array parameter."""
    element_type = _json_type_name(element_type)
    if element_type.lower() == "array":
        # `element_type` is a flat type name, so a nested array can only be
        # read as an array of strings — and it has to declare elements of its
        # own, because Gemini demands `items` at every level of an ARRAY.
        return List[str]
    return map_json_type_to_python(element_type)


def _http_tool_annotation(
    json_type: Optional[str] = None, element_type: Optional[str] = None
) -> Any:
    """Annotation ADK should advertise for a configured parameter type."""
    json_type = _json_type_name(json_type)
    if json_type.lower() == "array":
        # Gemini rejects an ARRAY parameter that carries no `items`, so an
        # array always declares an element type — string when none is given.
        return List[_http_tool_element_annotation(element_type)]
    return map_json_type_to_python(json_type)


def _sanitized_param_name(name: str) -> str:
    """The Python identifier standing in for a configured parameter name.

    A name that is already usable comes back byte for byte — the normal case.
    Anything else is rewritten deterministically, so a parameter the endpoint
    genuinely needs can still be declared instead of quietly disappearing.
    """
    candidate = "".join(char if f"a{char}".isidentifier() else "_" for char in name)
    if not candidate.isidentifier():
        # Empty, or beginning with a digit.
        candidate = f"p_{candidate}"
    if keyword.iskeyword(candidate) or candidate in ADK_RESERVED_PARAM_NAMES:
        candidate = f"{candidate}_"
    return candidate


def apply_http_tool_signature(
    http_tool: Callable[..., Any],
    *,
    path_params: Optional[Dict[str, Any]] = None,
    query_params: Optional[Dict[str, Any]] = None,
    body_params: Optional[Dict[str, Any]] = None,
    values: Optional[Dict[str, Any]] = None,
    body_type: str = "object",
    array_param: Optional[str] = None,
) -> Dict[str, str]:
    """Advertise a custom HTTP tool's configured parameters to the LLM.

    ADK derives a tool's input schema by walking ``inspect.signature`` and it
    skips ``VAR_KEYWORD`` outright, so a bare ``**kwargs`` closure is published
    with no properties at all — and ``FunctionTool.run_async`` then filters
    model-supplied arguments against that same signature and drops every one of
    them. Giving the closure a real keyword-only signature fixes both halves at
    once; the request-building body keeps reading its values out of ``kwargs``.

    A parameter is only mandatory when the configuration has no usable value
    for it, so tools that today send nothing but their static ``values`` keep
    working untouched.

    Returns the alias -> configured name mapping for the parameters whose
    configured name is not a usable Python identifier. The closure translates
    the model's arguments through it before building the request, so the
    endpoint still sees the name it was configured with.
    """
    path_params = path_params or {}
    query_params = query_params or {}
    body_params = body_params or {}
    values = values or {}

    declared: List[inspect.Parameter] = []
    seen = set()
    aliases: Dict[str, str] = {}
    # Every configured name that is already usable is claimed up front:
    # sanitising an awkward name must never steal the name another parameter
    # carries verbatim.
    taken = {
        name
        for group in (path_params, query_params, body_params)
        for name in group
        if isinstance(name, str) and _sanitized_param_name(name) == name
    }

    def declare(param: Any, annotation: Any, required: bool) -> None:
        if not isinstance(param, str):
            logger.warning(
                f"Skipping tool parameter {param!r}: a parameter name must be a "
                "string"
            )
            return
        if param in seen:
            return
        seen.add(param)

        # Names come from user-authored config, so they can be anything a JSON
        # key can be. An unusable one is declared under a stand-in identifier
        # rather than dropped: a required parameter that never reaches the
        # schema is a request that fires without it.
        alias = _sanitized_param_name(param)
        if alias != param:
            base = alias
            suffix = 2
            while alias in taken:
                alias = f"{base}_{suffix}"
                suffix += 1
            taken.add(alias)
            aliases[alias] = param

        declared.append(
            inspect.Parameter(
                alias,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=annotation,
                default=inspect.Parameter.empty if required else None,
            )
        )

    # A path placeholder leaves a broken URL behind when nothing fills it.
    for param in path_params:
        declare(param, str, required=param not in values)

    for param, configured in query_params.items():
        # A list-valued query param is joined and sent verbatim; the model has
        # no say over it, so it is not advertised.
        if isinstance(configured, list):
            continue
        # The configured scalar stays the fallback when the model says nothing.
        declare(param, str, required=False)

    if body_type == "array" and array_param:
        element = _param_config(body_params.get(array_param))
        declare(
            array_param,
            _http_tool_annotation("array", element.get("element_type")),
            # The array *is* the body here, so a required one that the config
            # cannot fill has to be asked of the model — otherwise the request
            # goes out as `[]`.
            required=bool(element.get("required")) and array_param not in values,
        )
    else:
        for param, param_config in body_params.items():
            param_config = _param_config(param_config)
            declare(
                param,
                _http_tool_annotation(
                    param_config.get("type"), param_config.get("element_type")
                ),
                required=bool(param_config.get("required")) and param not in values,
            )

    http_tool.__signature__ = inspect.Signature(declared)
    http_tool.__annotations__ = {p.name: p.annotation for p in declared}
    return aliases


def http_tool_doc_names(aliases: Dict[str, str]) -> Dict[str, str]:
    """Configured name -> the name the generated docstring should give it.

    ADK strips per-parameter descriptions out of the schema, so the docstring
    is the only place the model reads what a parameter means. Documenting a
    parameter under a configured name the schema does not publish invites the
    model to send that name, and ADK then filters the argument away — so the
    docstring leads with the alias. The configured name follows in brackets,
    so whoever wrote the configuration still recognises their own parameter.
    """
    return {
        configured: f"{alias} [{configured}]" for alias, configured in aliases.items()
    }


def exit_loop(tool_context: ToolContext):
    """Call this function ONLY when the process indicates no further iterations are needed, signaling the loop should end."""
    logger.info(f"[Tool Call] exit_loop triggered by {tool_context.agent_name}")
    tool_context.actions.escalate = True
    # Return empty dict as tools should typically return JSON-serializable output
    return {}



def _apply_vault_refs(tool_config, headers, _db=None):
    """Resolves headers that point at the credential vault.

    Opens its own short-lived session because neither tool builder carries one.
    Any failure falls back to the inline headers, so a vault outage degrades to
    today's behaviour instead of breaking the tool.
    """
    credential_refs = tool_config.get("credential_refs") or {}
    if not credential_refs:
        return headers

    from src.config.database import SessionLocal
    from src.services.adk.integration_credentials import (
        DatabaseCredentialVault,
        resolve_credential_refs,
    )
    from src.utils.crypto import decrypt_api_key

    session = SessionLocal()
    try:
        return resolve_credential_refs(
            headers,
            credential_refs,
            vault=DatabaseCredentialVault(session),
            decrypt=decrypt_api_key,
        )
    finally:
        session.close()

class CustomToolBuilder:
    def __init__(self):
        self.tools = []

    def _create_http_tool(self, tool_config: Dict[str, Any]) -> FunctionTool:
        """Create an HTTP tool based on the provided configuration."""
        name = tool_config["name"]
        description = tool_config["description"]
        endpoint = tool_config["endpoint"]
        method = tool_config["method"]
        headers = tool_config.get("headers", {})
        # A header pointing at the vault takes its value from there; the inline
        # one stays the fallback.
        headers = _apply_vault_refs(tool_config, headers)
        parameters = tool_config.get("parameters", {}) or {}
        values = strip_modes_meta(tool_config.get("values"))
        error_handling = tool_config.get("error_handling", {})

        path_params = parameters.get("path_params") or {}
        query_params = parameters.get("query_params") or {}
        body_params = parameters.get("body_params") or {}

        # Filled in below by `apply_http_tool_signature` for the parameters it
        # had to declare under a stand-in identifier.
        param_aliases: Dict[str, str] = {}

        def http_tool(**kwargs):
            try:
                # Back to the configured names, before anything reads them.
                if param_aliases:
                    kwargs = {
                        param_aliases.get(param, param): value
                        for param, value in kwargs.items()
                    }

                # Combines default values with provided values
                all_values = {**values, **kwargs}

                # Substitutes placeholders in headers
                processed_headers = {
                    k: v.format(**all_values) if isinstance(v, str) else v
                    for k, v in headers.items()
                }

                # Processes path parameters
                url = endpoint
                for param, value in path_params.items():
                    if param in all_values:
                        # URL encode the value for URL safe characters
                        replacement_value = urllib.parse.quote(
                            str(all_values[param]), safe=""
                        )
                        url = url.replace(f"{{{param}}}", replacement_value)

                # Process query parameters
                query_params_dict = {}
                for param, value in query_params.items():
                    if isinstance(value, list):
                        # If the value is a list, join with comma
                        # Unvalidated JSON: a raw join dies on the first number.
                        query_params_dict[param] = ",".join(str(item) for item in value)
                    elif param in all_values:
                        # If the parameter is in the values, use the provided value
                        query_params_dict[param] = all_values[param]
                    else:
                        # Otherwise, use the default value from the configuration
                        query_params_dict[param] = value

                # Adds default values to query params if they are not present.
                # Reads the merge, not the raw defaults: a value the model
                # overrode must not travel as the canned one here and as the
                # override in the body.
                for param, value in values.items():
                    if param not in query_params_dict and param not in path_params:
                        query_params_dict[param] = all_values.get(param, value)

                body_data = {}
                for param, param_config in body_params.items():
                    if param in all_values:
                        body_data[param] = all_values[param]

                # Adds default values to body if they are not present
                for param, value in values.items():
                    if (
                        param not in body_data
                        and param not in query_params_dict
                        and param not in path_params
                    ):
                        body_data[param] = all_values.get(param, value)

                # Makes the HTTP request
                response = requests.request(
                    method=method,
                    url=url,
                    headers=processed_headers,
                    params=query_params_dict,
                    json=body_data if body_data else None,
                    timeout=error_handling.get("timeout", 30),
                )

                if response.status_code >= 400:
                    raise requests.exceptions.HTTPError(
                        f"Error in the request: {response.status_code} - {response.text}"
                    )

                # Try to parse the response as JSON, if it fails, return the text content
                try:
                    return json.dumps(response.json())
                except ValueError:
                    # Response is not JSON, return the text content
                    return json.dumps({"content": response.text})

            except Exception as e:
                logger.error(f"Error executing tool {name}: {str(e)}")
                return json.dumps(
                    error_handling.get(
                        "fallback_response",
                        {"error": "tool_execution_error", "message": str(e)},
                    )
                )

        # Without a real signature ADK advertises no parameters at all and
        # discards whatever the model sends, leaving only the static `values`.
        param_aliases.update(
            apply_http_tool_signature(
                http_tool,
                path_params=path_params,
                query_params=query_params,
                body_params=body_params,
                values=values,
            )
        )

        # Adds dynamic docstring based on the configuration. Built after the
        # signature, because a parameter declared under a stand-in identifier
        # has to be documented under the name the model is actually offered.
        doc_names = http_tool_doc_names(param_aliases)
        param_docs = []

        # Adds path parameters
        for param, value in path_params.items():
            param_docs.append(f"{doc_names.get(param, param)}: {value}")

        # Adds query parameters
        for param, value in query_params.items():
            if isinstance(value, list):
                # The configured list is sent verbatim, and it is unvalidated
                # JSON: joining it raw breaks the build on the first number.
                joined = ", ".join(str(item) for item in value)
                param_docs.append(f"{doc_names.get(param, param)}: List[{joined}]")
            else:
                param_docs.append(f"{doc_names.get(param, param)}: {value}")

        # Adds body parameters. Read through the same coercers the signature
        # uses: a config missing `description`, or that is not a dict at all,
        # must not be the reason an agent fails to build.
        for param, param_config in body_params.items():
            param_config = _param_config(param_config)
            required = "Required" if param_config.get("required", False) else "Optional"
            json_type = _json_type_name(param_config.get("type"))
            param_description = param_config.get("description")
            described = f": {param_description}" if param_description else ""
            param_docs.append(
                f"{doc_names.get(param, param)} ({json_type}, {required}){described}"
            )

        # Adds default values
        if values:
            param_docs.append("\nDefault values:")
            for param, value in values.items():
                param_docs.append(f"{doc_names.get(param, param)}: {value}")

        http_tool.__doc__ = f"""
        {description}

        Parameters:
        {chr(10).join(param_docs)}

        Returns:
        String containing the response in JSON format
        """

        # Defines the function name to be used by the ADK
        http_tool.__name__ = name

        return FunctionTool(func=http_tool)

    def _create_exit_loop_tool(self) -> FunctionTool:
        """Create the exit_loop tool for LoopAgent."""
        return FunctionTool(func=exit_loop)

    def build_tools(
        self, tools_config: Dict[str, Any], db=None
    ) -> List[FunctionTool]:
        """Builds a list of tools based on the provided configuration.

        Accepts:
        - 'custom_tool_ids': List of IDs to fetch from database
        - 'custom_tools' with 'http_tools': Direct tool configurations
        - 'http_tools': Direct tool configurations
        - 'tools' with 'http_tools': Direct tool configurations

        Args:
            tools_config: Configuration dictionary containing tool definitions or IDs
            db: Database session (required when using custom_tool_ids)
        """
        self.tools = []

        # Process custom_tool_ids - fetch from database
        custom_tool_ids = tools_config.get("custom_tool_ids", [])
        if custom_tool_ids:
            if not db:
                logger.error(
                    "Database session is required when using custom_tool_ids"
                )
                raise ValueError(
                    "Database session is required when using custom_tool_ids"
                )

            from src.services import custom_tool_service
            import uuid

            logger.info(f"Processing {len(custom_tool_ids)} custom tool IDs")

            for tool_id_str in custom_tool_ids:
                try:
                    # Convert to UUID and get from database
                    tool_id = uuid.UUID(str(tool_id_str))
                    custom_tool = custom_tool_service.get_custom_tool(db, tool_id)

                    if not custom_tool:
                        logger.warning(f"Custom tool not found: {tool_id_str}")
                        continue

                    # Convert database model to tool configuration format
                    tool_config = {
                        "name": custom_tool.name,
                        "description": custom_tool.description or "",
                        "method": custom_tool.method,
                        "endpoint": custom_tool.endpoint,
                        "headers": custom_tool.headers or {},
                        "parameters": {
                            "path_params": custom_tool.path_params or {},
                            "query_params": custom_tool.query_params or {},
                            "body_params": custom_tool.body_params or {},
                        },
                        "values": custom_tool.values or {},
                        "error_handling": custom_tool.error_handling
                        or {
                            "timeout": 30,
                            "retry_count": 0,
                            "fallback_response": {"error": "", "message": ""},
                        },
                    }

                    # Create and add the tool
                    http_tool = self._create_http_tool(tool_config)
                    self.tools.append(http_tool)
                    logger.info(f"Added custom tool from database: {custom_tool.name}")

                except Exception as e:
                    logger.error(f"Error processing custom tool ID {tool_id_str}: {e}")
                    continue

        # Process direct http_tools configurations
        http_tools = []
        if tools_config.get("http_tools"):
            http_tools = tools_config.get("http_tools", [])
        elif tools_config.get("custom_tools") and tools_config["custom_tools"].get(
            "http_tools"
        ):
            http_tools = tools_config["custom_tools"].get("http_tools", [])
        elif (
            tools_config.get("tools")
            and isinstance(tools_config["tools"], dict)
            and tools_config["tools"].get("http_tools")
        ):
            http_tools = tools_config["tools"].get("http_tools", [])

        built_from_ids = {tool.func.__name__ for tool in self.tools}
        for http_tool_config in http_tools:
            # The http_tools of an agent that also carries custom_tool_ids are those
            # same tools expanded into its config. Building both registers the tool
            # twice under one name.
            if http_tool_config.get("name") in built_from_ids:
                logger.debug(
                    f"Skipping http_tool '{http_tool_config.get('name')}': "
                    "already built from custom_tool_ids"
                )
                continue
            self.tools.append(self._create_http_tool(http_tool_config))

        # Add exit_loop tool if specified in configuration
        if tools_config.get("enable_exit_loop", False):
            self.tools.append(self._create_exit_loop_tool())

        logger.info(f"Built {len(self.tools)} custom tools total")
        return self.tools
