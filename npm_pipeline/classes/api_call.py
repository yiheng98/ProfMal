from typing import Any, Dict, List, Optional, Tuple
import json
from sensitive_op import sensitive_call_finder


class APICall:
    def __init__(
        self,
        _type: str,
        timestamp: str,
        module: str,
        function: str,
        caller: Dict[str, Any],
        arguments: List[Any],
        result: Any,
    ):
        """
        Initializes an APICall instance with the provided details.
        """
        self.type = _type
        self.timestamp = timestamp
        self.module = module
        self.function = function
        self.caller = caller  # Expected to be a dict with keys 'file', 'line', 'column'
        self.arguments = arguments
        self.result = result


class APICallCollection:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.collections = []
        self._read_api_call_logs(self.file_path)

    def _read_api_call_logs(self, file_path: str):
        """
        Reads the JSON file and returns a list of APICallLog instances.
        """
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            for entry in data:
                _type = entry.get("type", None)
                timestamp = entry.get("timestamp")
                module = entry.get("module")
                function = entry.get("function")
                caller = entry.get("caller", {})
                arguments = entry.get("arguments", [])
                result = entry.get("result")
                if caller:
                    if caller.get("file", None) is not None and caller.get("file", None).startswith("node"):
                        pass
                    else:
                        full_name = f"{module}.{function}"
                        if sensitive_call_finder.query(full_name):
                            api_call = APICall(_type, timestamp, module, function, caller, arguments, result)
                            self.add_api_call(api_call)

    def add_api_call(self, api_call: APICall):
        """
        Adds a new API call to the collection. If an API call with the same caller's
        file, line, and column exists, remove the original and append the new one.
        """
        new_caller = api_call.caller
        file_val = new_caller.get("file", None)
        start_line_val = new_caller.get("start_line", None)
        start_column_val = new_caller.get("start_column", None)
        end_line_val = new_caller.get("end_line", None)
        end_column_val = new_caller.get("end_column", None)

        # Only perform the check if all caller info is present
        if (
            file_val is not None
            and start_line_val is not None
            and start_column_val is not None
            and end_line_val is not None
            and end_column_val is not None
        ):
            # Remove any API call with matching caller file, line, and column.
            self.collections = [
                call
                for call in self.collections
                if not (
                    call.caller.get("file") == file_val
                    and call.caller.get("start_line") == start_line_val
                    and call.caller.get("start_column") == start_column_val
                    and call.caller.get("end_line") == end_line_val
                    and call.caller.get("end_column") == end_column_val
                )
            ]
        # Append the new API call at the end.
        self.collections.append(api_call)

    def find_api_call(
        self, _type: str, file: str, start_line: int, start_column: int, end_line: int, end_column: int
    ) -> Optional[Tuple[str, str]]:
        """
        Searches the stored API call logs for an entry with a matching caller location.
        Returns a tuple (module, function) if found, or None otherwise.
        """
        for api_call in self.collections:
            caller = api_call.caller
            call_type = api_call.type
            if (
                _type == call_type
                and caller.get("file") == file
                and caller.get("start_line") == start_line
                and caller.get("start_column") == start_column
                and caller.get("end_line") == end_line
                and caller.get("end_column") == end_column
            ):
                return api_call
        return None
