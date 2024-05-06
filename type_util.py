from typing import Any, Sequence
from datetime import datetime

# データ型処理用のutil ----------------------------------------------------------------

def is_type(val: Any, type_list: list) -> bool:
    for type in type_list:
        if isinstance(val, type):
            return True
    return False


def _convert_date_type(time: datetime) -> int:
    return int(time.timestamp() * 1000)


def _convert_value_to_json_serializable(val: Any) -> Any:
    if isinstance(val, datetime):
        return _convert_date_type(val)
    elif isinstance(val, Timestamp):
        return _convert_date_type(val.as_datetime())
    elif isinstance(val, ObjectId):
        return str(val)
    elif isinstance(val, dict):
        return {k: _convert_value_to_json_serializable(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_convert_value_to_json_serializable(v) for v in val]
    else:
        return val


def convert_dict_to_json_serializable(dictionary: dict) -> dict:
    return {k: _convert_value_to_json_serializable(v) for k, v in dictionary.items()}


def convert_array_of_dict_to_json_serializable(documents: Sequence[dict]) -> list:
    return list(map(convert_dict_to_json_serializable, documents))

